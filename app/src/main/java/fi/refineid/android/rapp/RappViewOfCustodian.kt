// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import uniffi.refineid_rapp.rappRedialWindowMs

/**
 * The requester's view of its paired custodian (RAPP v26.11.2 section 4.7,
 * `requester_view_of_custodian`): whether a session is up, and whether to
 * dial. One instance runs while remote use is on with an active pairing;
 * discovery stopping or the pairing ending moves it to [State.ENDED], and
 * discovery started later starts a new one in [State.IDLE].
 *
 * The driver feeds discovery edges, dial results and session ends, and
 * carries out the returned [Action]s: dials, redial timers, the offer
 * grace, and the identity. Time is the driver's monotonic milliseconds.
 * Events the machine cannot take in its state, including the ones the
 * state machine rules out, are ignored and return no action.
 *
 * This device dials over the stream transport only, so a record appearing
 * while a dial runs is left to that dial: the running browse already
 * resolves it. There is no BLE advertisement handling.
 */
internal class RappViewOfCustodian {
    /** Where the paired custodian stands. */
    enum class State {
        /** No session, no redial window: dial only on appearance or a consumer. */
        IDLE,

        /** A dial is being set up, or due on the back-off within the redial window. */
        CONNECTING,

        /** The session is healthy. */
        CONNECTED,

        /** Verified withdrawal: no dial and no offer until the next announcement. */
        WITHDRAWN,

        /** The pairing stopped being active, or discovery stopped. */
        ENDED,
    }

    /** What the driver reports. */
    sealed interface Event {
        /** A `mode=session` record for the pairing appeared: first sight, a fresh instance, or back. */
        data object RecordAppeared : Event

        /** A withdrawn record verified on the associated instance (section 4.5 item 6). */
        data object WithdrawnRecordMatched : Event

        /** A sight of the custodian went; the redial window, if any, runs on. */
        data object SightLost : Event

        /** A local consumer asked for the card with no session open. */
        data object ConsumerRequest : Event

        /** The back-off within the redial window passed. */
        data object RedialDue : Event

        /** The redial window passed; [dialRunning] says whether a dial is still being set up. */
        data class RedialWindowEnded(
            val dialRunning: Boolean,
        ) : Event

        /** `session.ready` verified. */
        data object DialSucceeded : Event

        /** The dial ended before `session.ready`. */
        data object DialFailed : Event

        /** `pairing_revoked` received, or the revoking close in place of `session.ready`. */
        data object PairingRevoked : Event

        /** `service_withdrawn` or `card_unavailable` received. */
        data object Withdrawn : Event

        /** An authenticated protocol violation, received or detected. */
        data object ProtocolViolation : Event

        /** A transport loss, the silence limit, an AEAD or framing failure, or any other close. */
        data object SessionLost : Event

        /** The pairing stopped being active on this requester, or discovery stopped. */
        data object PairingLeft : Event
    }

    /** What the driver does. */
    sealed interface Action {
        /** Open a session dial now; in [State.CONNECTING] only when none runs. */
        data object OpenDial : Action

        /** Drop the dial being set up. */
        data object AbortDial : Action

        /** Dial again after [delayMs]; the driver raises [Event.RedialDue] then. */
        data class ScheduleRedial(
            val delayMs: Long,
        ) : Action

        /** The redial window ended; drop its timers. */
        data object EndRedialWindow : Action

        /** Keep offering the identity through the grace of section 8.4 item 3. */
        data object StartOfferGrace : Action

        /** Stop offering the custodian's identity at once. */
        data object WithdrawIdentity : Action

        /** The custodian revoked the pairing: it forgot this computer. */
        data object ShowPeerForgot : Action

        /** Answer the waiting consumer at once that no remote card is available. */
        data object RefuseConsumer : Action

        /** Close the open session with this requester's own close. */
        data object RequestLocalClose : Action
    }

    var state: State = State.IDLE
        private set

    /**
     * When the redial window ends, in the driver's monotonic milliseconds, or
     * null while none runs. The driver raises [Event.RedialWindowEnded] then.
     */
    var redialWindowUntilMs: Long? = null
        private set

    /** Redials scheduled within the running window, which spaces the back-off. */
    private var redialsScheduled = 0

    /**
     * Feeds [event] at [nowMs] and returns the actions, in the order the
     * state machine lists them.
     */
    fun event(
        event: Event,
        nowMs: Long,
    ): List<Action> =
        when (state) {
            State.IDLE -> idle(event)
            State.CONNECTING -> connecting(event, nowMs)
            State.CONNECTED -> connected(event, nowMs)
            State.WITHDRAWN -> withdrawn(event)
            State.ENDED -> emptyList()
        }

    private fun idle(event: Event): List<Action> =
        when (event) {
            Event.RecordAppeared, Event.ConsumerRequest -> {
                state = State.CONNECTING
                listOf(Action.OpenDial)
            }

            Event.WithdrawnRecordMatched -> {
                state = State.WITHDRAWN
                listOf(Action.WithdrawIdentity)
            }

            Event.PairingLeft -> {
                state = State.ENDED
                listOf(Action.WithdrawIdentity)
            }

            else -> {
                emptyList()
            }
        }

    private fun connecting(
        event: Event,
        nowMs: Long,
    ): List<Action> =
        when (event) {
            Event.RecordAppeared, Event.RedialDue -> {
                state = State.CONNECTING
                if (event == Event.RecordAppeared) {
                    listOf(Action.AbortDial, Action.OpenDial)
                } else {
                    listOf(Action.OpenDial)
                }
            }

            Event.WithdrawnRecordMatched -> {
                endWindow()
                state = State.WITHDRAWN
                listOf(Action.AbortDial, Action.EndRedialWindow, Action.WithdrawIdentity)
            }

            Event.Withdrawn -> {
                endWindow()
                state = State.WITHDRAWN
                listOf(Action.AbortDial, Action.EndRedialWindow, Action.WithdrawIdentity)
            }

            Event.ConsumerRequest -> {
                state = State.CONNECTING
                listOf(Action.OpenDial)
            }

            is Event.RedialWindowEnded -> {
                if (event.dialRunning) {
                    emptyList()
                } else {
                    endWindow()
                    state = State.IDLE
                    listOf(Action.EndRedialWindow)
                }
            }

            Event.DialSucceeded -> {
                endWindow()
                state = State.CONNECTED
                listOf(Action.EndRedialWindow)
            }

            Event.DialFailed -> {
                if (windowSpent(nowMs)) {
                    endWindow()
                    state = State.IDLE
                    listOf(Action.EndRedialWindow)
                } else {
                    openWindow(nowMs)
                    state = State.CONNECTING
                    listOf(Action.ScheduleRedial(nextBackoffMs()))
                }
            }

            Event.PairingRevoked -> {
                endWindow()
                state = State.ENDED
                listOf(Action.WithdrawIdentity, Action.ShowPeerForgot)
            }

            Event.ProtocolViolation -> {
                endWindow()
                state = State.IDLE
                listOf(Action.AbortDial, Action.EndRedialWindow)
            }

            Event.PairingLeft -> {
                endWindow()
                state = State.ENDED
                listOf(Action.AbortDial, Action.EndRedialWindow, Action.WithdrawIdentity)
            }

            else -> {
                emptyList()
            }
        }

    private fun connected(
        event: Event,
        nowMs: Long,
    ): List<Action> =
        when (event) {
            Event.PairingRevoked -> {
                state = State.ENDED
                listOf(Action.WithdrawIdentity, Action.ShowPeerForgot)
            }

            Event.Withdrawn -> {
                state = State.WITHDRAWN
                listOf(Action.WithdrawIdentity)
            }

            Event.ProtocolViolation -> {
                state = State.IDLE
                listOf(Action.StartOfferGrace)
            }

            Event.SessionLost -> {
                openWindow(nowMs)
                state = State.CONNECTING
                listOf(Action.StartOfferGrace, Action.ScheduleRedial(nextBackoffMs()))
            }

            Event.PairingLeft -> {
                state = State.ENDED
                listOf(Action.WithdrawIdentity, Action.RequestLocalClose)
            }

            else -> {
                emptyList()
            }
        }

    private fun withdrawn(event: Event): List<Action> =
        when (event) {
            Event.RecordAppeared -> {
                state = State.CONNECTING
                listOf(Action.OpenDial)
            }

            Event.ConsumerRequest -> {
                listOf(Action.RefuseConsumer)
            }

            Event.PairingLeft -> {
                state = State.ENDED
                listOf(Action.WithdrawIdentity)
            }

            else -> {
                emptyList()
            }
        }

    /** Whether the redial window has run out at [nowMs]. */
    private fun windowSpent(nowMs: Long): Boolean {
        val untilMs = redialWindowUntilMs ?: return false
        return nowMs >= untilMs
    }

    /**
     * Opens the redial window at [nowMs] when none runs: a loss opens it at
     * once, and otherwise the first failed dial since the custodian last
     * appeared (section 8.3 item 3).
     */
    private fun openWindow(nowMs: Long) {
        if (redialWindowUntilMs == null) {
            redialWindowUntilMs = nowMs + REDIAL_WINDOW_MS
            redialsScheduled = 0
        }
    }

    private fun endWindow() {
        redialWindowUntilMs = null
        redialsScheduled = 0
    }

    /** The next redial's back-off: doubled from the first, up to the longest. */
    private fun nextBackoffMs(): Long {
        var delayMs = FIRST_REDIAL_DELAY_MS
        repeat(redialsScheduled) { delayMs = (delayMs * REDIAL_BACKOFF_FACTOR).coerceAtMost(MAX_REDIAL_DELAY_MS) }
        redialsScheduled++
        return delayMs
    }

    companion object {
        /** How long a loss is redialed, counted from the loss (section 8.3 item 3). */
        val REDIAL_WINDOW_MS: Long = rappRedialWindowMs().toLong()

        /** The first redial's back-off, doubled for each redial after it. */
        const val FIRST_REDIAL_DELAY_MS = 1_000L

        /** The longest back-off between two redials. */
        const val MAX_REDIAL_DELAY_MS = 10_000L

        /** By how much each redial's back-off grows over the previous one. */
        const val REDIAL_BACKOFF_FACTOR = 2L
    }
}
