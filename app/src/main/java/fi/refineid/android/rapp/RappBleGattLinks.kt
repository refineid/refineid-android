// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

/**
 * The answer to one ATT request. A refusal is never an authentication,
 * authorization or encryption error, which would make the central's system
 * start bonding (STPA CC-54, CC-73).
 */
internal enum class RappBleAttAnswer {
    SUCCESS,
    WRITE_NOT_PERMITTED,
    READ_NOT_PERMITTED,
}

/** The attribute an ATT request names. */
internal enum class RappBleAttribute {
    CHANNEL,
    CHANNEL_CCCD,
    BOOTSTRAP,
    OTHER,
}

/** One ATT write the platform delivered, with the way to answer it. */
internal class RappBleWrite<D : Any>(
    val device: D,
    val attribute: RappBleAttribute,
    /** The whole value in one write: not a prepared write of a long write, and at offset zero. */
    val whole: Boolean,
    /** A write request; false for a write command, which has no answer. */
    val responseNeeded: Boolean,
    val value: ByteArray?,
    private val respond: (RappBleAttAnswer) -> Unit,
) {
    /** Answers the request; a write command gets no answer. */
    fun answer(answer: RappBleAttAnswer) {
        if (responseNeeded) respond(answer)
    }
}

/** One ATT read the platform delivered, with the way to answer it. */
internal class RappBleRead<D : Any>(
    val device: D,
    val attribute: RappBleAttribute,
    val offset: Int,
    val answer: (RappBleAttAnswer, ByteArray?) -> Unit,
)

/** What the link table needs from the platform, on the server's lane. */
internal interface RappBleGattPort<D : Any> {
    /** Starts indicating [fragment] on the channel to [device]; false when the platform refused. */
    fun indicate(
        device: D,
        fragment: ByteArray,
    ): Boolean

    /** Runs [action] on the lane after [delayMs]. */
    fun schedule(
        delayMs: Long,
        action: () -> Unit,
    )

    /** Monotonic milliseconds, the clock the SAR deadline runs on. */
    fun nowMs(): ULong
}

/**
 * The custodian's GATT links of `fi.refineid.rapp.ble` (RAPP v26.10.29
 * sections 5.2 and 5.3).
 *
 * Each central that enables indications on the channel opens a link of its
 * own. The link takes no write before that, reads the capacity of the ATT MTU
 * negotiated by then and starts closed below 512, routes one preamble through
 * [admits], then carries frames written to it and indicated back, one
 * fragment in flight per central. A refused preamble, a refused fragment and
 * a write on a closed link are answered `writeNotPermitted`, never an
 * authentication or encryption error (CC-54, CC-73). A closed link refuses
 * writes until its central disables indications or disconnects. The owner's
 * close indicates the frames queued before it, within
 * [RappBleGattProfile.CLOSE_DRAIN_LIMIT_MS], then ends the link.
 *
 * Confined to the server's lane: every call, every [admits] and every
 * [onEvent] runs there.
 */
internal class RappBleGattLinks<D : Any>(
    private val port: RappBleGattPort<D>,
    private val admits: (preamble: ByteArray, link: RappBleLink) -> Boolean,
    private val onEvent: (RappBleGattEvent) -> Unit,
) {
    private val attMtus = HashMap<D, Int>()
    private val links = HashMap<D, RappBleLinkState>()
    private val indicating = HashSet<D>()
    private var serial = 0L
    private var whenShutDown: (() -> Unit)? = null

    /** Whether [shutdown] began: no central subscribes and no preamble routes. */
    var isFinished: Boolean = false
        private set

    /** The ATT MTU the central [device] negotiated. */
    fun mtuChanged(
        device: D,
        attMtu: Int,
    ) {
        attMtus[device] = attMtu
    }

    /** The central [device] disconnected; its link ends. */
    fun disconnected(device: D) {
        attMtus.remove(device)
        indicating.remove(device)
        links.remove(device)?.let { state ->
            end(state, RappBleLinkFailure.DISCONNECTED)
            onEvent(RappBleGattEvent.Unsubscribed(state.link))
            state.close()
        }
        settleShutdown()
    }

    /** One write on the channel or its configuration descriptor; anything else is refused. */
    fun write(request: RappBleWrite<D>) {
        when (request.attribute) {
            RappBleAttribute.CHANNEL -> channelWrite(request)
            RappBleAttribute.CHANNEL_CCCD -> configurationWrite(request)
            RappBleAttribute.BOOTSTRAP, RappBleAttribute.OTHER -> request.answer(RappBleAttAnswer.WRITE_NOT_PERMITTED)
        }
    }

    /**
     * One read: the channel's configuration for this central. The bootstrap
     * characteristic carries an offer only while pairing, which this server
     * does not serve, and the channel itself carries no frame on a read
     * (section 5.2).
     */
    fun read(request: RappBleRead<D>) {
        if (request.attribute != RappBleAttribute.CHANNEL_CCCD || request.offset != 0) {
            request.answer(RappBleAttAnswer.READ_NOT_PERMITTED, null)
            return
        }
        val configuration = if (request.device in links) RappBleCccd.INDICATIONS else RappBleCccd.DISABLED
        request.answer(RappBleAttAnswer.SUCCESS, configuration.wire())
    }

    /** The central [device] confirmed the indication in flight, or [delivered] is false when it failed. */
    fun notificationSent(
        device: D,
        delivered: Boolean,
    ) {
        if (!indicating.remove(device)) return
        val state = links[device]
        when {
            state == null -> {}

            delivered -> {
                drain(device, state)
            }

            else -> {
                end(state, RappBleLinkFailure.INDICATION_FAILED)
            }
        }
        settleShutdown()
    }

    /** Indicates [frame] on [link], fragment by fragment; nothing when the link no longer serves. */
    fun send(
        link: RappBleLink,
        frame: ByteArray,
    ) {
        val (device, state) = find(link) ?: return
        if (state.phase != RappBleLinkState.Phase.OPEN || !state.routed) return
        if (!state.enqueue(frame)) {
            end(state, RappBleLinkFailure.PROTOCOL_VIOLATION)
            return
        }
        drain(device, state)
    }

    /** Ends [link] once the frames already queued on it are indicated, or the drain limit passes. */
    fun close(link: RappBleLink) {
        val (_, state) = find(link) ?: return
        if (state.phase != RappBleLinkState.Phase.OPEN) return
        if (state.drained) {
            end(state, RappBleLinkFailure.CANCELLED)
            return
        }
        state.beginClosing()
        port.schedule(RappBleGattProfile.CLOSE_DRAIN_LIMIT_MS) {
            if (state.phase == RappBleLinkState.Phase.CLOSING) end(state, RappBleLinkFailure.CANCELLED)
            settleShutdown()
        }
    }

    /** Bluetooth turned off: the platform dropped every connection and the service with them. */
    fun radioDown() {
        links.values.forEach { state ->
            end(state, RappBleLinkFailure.BLUETOOTH_UNAVAILABLE)
            state.close()
        }
        links.clear()
        attMtus.clear()
        indicating.clear()
        settleShutdown()
    }

    /**
     * Ends every link, letting each indicate what it already queued, and
     * calls [done] once none is left closing; no link opens from now on.
     */
    fun shutdown(done: () -> Unit) {
        isFinished = true
        whenShutDown = done
        links.values.toList().forEach { close(it.link) }
        settleShutdown()
    }

    /** Opens a link at the subscription, or refuses the configuration the channel does not permit. */
    private fun configurationWrite(request: RappBleWrite<D>) {
        val configuration = RappBleCccd.of(request.value).takeIf { request.whole }
        if (configuration == null || (isFinished && configuration == RappBleCccd.INDICATIONS)) {
            request.answer(RappBleAttAnswer.WRITE_NOT_PERMITTED)
            return
        }
        val device = request.device
        links.remove(device)?.let { previous ->
            end(previous, RappBleLinkFailure.DISCONNECTED)
            onEvent(RappBleGattEvent.Unsubscribed(previous.link))
            previous.close()
        }
        if (configuration == RappBleCccd.INDICATIONS) {
            val attMtu = attMtus[device] ?: RappBleGattProfile.DEFAULT_ATT_MTU
            val capacity = RappBleSarCapacity.forAttMtu(attMtu)
            val state = RappBleLinkState(RappBleLink(++serial), capacity)
            links[device] = state
            onEvent(RappBleGattEvent.Subscribed(state.link, attMtu, accepted = capacity != null))
            if (capacity == null) onEvent(RappBleGattEvent.Closed(state.link, RappBleLinkFailure.ATT_MTU_TOO_SMALL))
        }
        request.answer(RappBleAttAnswer.SUCCESS)
        settleShutdown()
    }

    /** Takes one fragment on the channel: the preamble routes the link, every later frame goes to the owner. */
    private fun channelWrite(request: RappBleWrite<D>) {
        val state = links[request.device]
        if (state == null || state.phase != RappBleLinkState.Phase.OPEN) {
            request.answer(RappBleAttAnswer.WRITE_NOT_PERMITTED)
            return
        }
        if (!request.whole || !request.responseNeeded) {
            end(state, RappBleLinkFailure.PROTOCOL_VIOLATION)
            request.answer(RappBleAttAnswer.WRITE_NOT_PERMITTED)
            return
        }
        val answer =
            when (val receipt = state.receive(request.value ?: ByteArray(0), port.nowMs())) {
                RappBleReceipt.Refused -> {
                    end(state, RappBleLinkFailure.REASSEMBLY_FAILED)
                    RappBleAttAnswer.WRITE_NOT_PERMITTED
                }

                RappBleReceipt.Partial -> {
                    port.schedule(RappBleGattProfile.REASSEMBLY_TIMEOUT_MS) {
                        if (state.phase == RappBleLinkState.Phase.OPEN && state.reassemblyExpired(port.nowMs())) {
                            end(state, RappBleLinkFailure.REASSEMBLY_FAILED)
                        }
                    }
                    RappBleAttAnswer.SUCCESS
                }

                is RappBleReceipt.Complete -> {
                    if (state.routed) {
                        onEvent(RappBleGattEvent.Frame(state.link, receipt.frame))
                        RappBleAttAnswer.SUCCESS
                    } else if (!isFinished && admits(receipt.frame, state.link)) {
                        state.routed = true
                        onEvent(RappBleGattEvent.Routed(state.link))
                        RappBleAttAnswer.SUCCESS
                    } else {
                        end(state, RappBleLinkFailure.ROUTING_REFUSED)
                        RappBleAttAnswer.WRITE_NOT_PERMITTED
                    }
                }
            }
        request.answer(answer)
    }

    /** Starts the next indication to [device] unless one is in flight; a closing link ends once drained. */
    private fun drain(
        device: D,
        state: RappBleLinkState,
    ) {
        if (device in indicating || state.phase == RappBleLinkState.Phase.CLOSED) return
        val fragment = state.nextFragment()
        when {
            fragment == null -> {
                if (state.phase ==
                    RappBleLinkState.Phase.CLOSING
                ) {
                    end(state, RappBleLinkFailure.CANCELLED)
                }
            }

            port.indicate(device, fragment) -> {
                indicating += device
            }

            else -> {
                end(state, RappBleLinkFailure.INDICATION_FAILED)
            }
        }
    }

    /** Ends [state] once, telling the owner why. */
    private fun end(
        state: RappBleLinkState,
        failure: RappBleLinkFailure,
    ) {
        if (state.phase == RappBleLinkState.Phase.CLOSED) return
        state.end()
        onEvent(RappBleGattEvent.Closed(state.link, failure))
    }

    private fun find(link: RappBleLink): Pair<D, RappBleLinkState>? =
        links.entries.firstOrNull { it.value.link == link }?.let { it.key to it.value }

    /** Completes a shutdown once no link is left closing. */
    private fun settleShutdown() {
        val done = whenShutDown ?: return
        if (links.values.any { it.phase == RappBleLinkState.Phase.CLOSING }) return
        whenShutDown = null
        links.values.forEach { it.close() }
        links.clear()
        attMtus.clear()
        indicating.clear()
        done()
    }
}
