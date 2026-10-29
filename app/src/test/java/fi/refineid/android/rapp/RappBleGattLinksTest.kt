// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import uniffi.refineid_rapp.RappBleSarReassembler
import uniffi.refineid_rapp.rappBleSarSegment

/**
 * The custodian's GATT links (RAPP v26.10.29 sections 5.2 and 5.3) against a
 * fake platform: subscription, the MTU floor, routing, refusal, reassembly,
 * indications one at a time, the owner's close, and the server's shutdown.
 * Every refusal is `writeNotPermitted`, never an authentication or
 * encryption error (STPA CC-54, CC-73).
 */
class RappBleGattLinksTest {
    private companion object {
        const val CENTRAL = "central-a"
        const val OTHER_CENTRAL = "central-b"
        const val ACCEPTED_ATT_MTU = RappBleGattProfile.MINIMUM_ATT_MTU
        const val SMALL_ATT_MTU = RappBleGattProfile.MINIMUM_ATT_MTU - 1
        const val PREAMBLE = "synthetic routing preamble"
        const val FRAME = "synthetic session frame"

        /** Long enough to need several fragments at the minimum MTU. */
        const val LONG_FRAME_REPEATS = 100
        val LONG_FRAME = FRAME.repeat(LONG_FRAME_REPEATS)

        /** Shorter than one SAR header (section 5.3). */
        const val TRUNCATED_FRAGMENT = "abc"

        /** The configuration bit that enables notifications (Bluetooth Core v5.4, Vol 3, Part G, 3.3.3.3). */
        const val NOTIFICATIONS_BIT = 0

        /** The configuration value is little-endian: its low octet comes first. */
        const val LOW_OCTET = 0

        /** A read of a whole value. */
        const val NO_OFFSET = 0
    }

    /** A platform that records what the server did and runs its timers on a clock the test moves. */
    private class FakePort : RappBleGattPort<String> {
        var now = 0UL
        var refuseIndications = false
        val indications = mutableListOf<Pair<String, ByteArray>>()
        private val timers = mutableListOf<Pair<ULong, () -> Unit>>()

        override fun indicate(
            device: String,
            fragment: ByteArray,
        ): Boolean {
            if (refuseIndications) return false
            indications += device to fragment
            return true
        }

        override fun schedule(
            delayMs: Long,
            action: () -> Unit,
        ) {
            timers += (now + delayMs.toULong()) to action
        }

        override fun nowMs(): ULong = now

        fun advance(delayMs: Long) {
            now += delayMs.toULong()
            val due = timers.filter { it.first <= now }
            timers.removeAll(due)
            due.forEach { it.second() }
        }
    }

    private val port = FakePort()
    private val events = mutableListOf<RappBleGattEvent>()
    private val admitted = mutableListOf<String>()
    private var admitting = true
    private lateinit var links: RappBleGattLinks<String>

    @Before
    fun setUp() {
        RappNativeTestLibrary.require()
        links =
            RappBleGattLinks(port, { preamble, _ ->
                admitted += preamble.decodeToString()
                admitting
            }) { events += it }
    }

    private fun capacity(): UInt = checkNotNull(RappBleSarCapacity.forAttMtu(ACCEPTED_ATT_MTU)).bytes

    private fun write(
        attribute: RappBleAttribute,
        value: ByteArray?,
        device: String = CENTRAL,
        whole: Boolean = true,
        responseNeeded: Boolean = true,
    ): RappBleAttAnswer? {
        var answer: RappBleAttAnswer? = null
        links.write(RappBleWrite(device, attribute, whole, responseNeeded, value) { answer = it })
        return answer
    }

    private fun subscribe(
        device: String = CENTRAL,
        attMtu: Int? = ACCEPTED_ATT_MTU,
    ): RappBleAttAnswer? {
        if (attMtu != null) links.mtuChanged(device, attMtu)
        return write(RappBleAttribute.CHANNEL_CCCD, RappBleCccd.INDICATIONS.wire(), device)
    }

    /** Writes [message] as the SAR fragments that carry it; the answer to each fragment. */
    private fun send(
        message: String,
        device: String = CENTRAL,
    ): List<RappBleAttAnswer?> =
        rappBleSarSegment(message.encodeToByteArray(), capacity()).map { write(RappBleAttribute.CHANNEL, it, device) }

    private fun linkOf(event: RappBleGattEvent): RappBleLink =
        when (event) {
            is RappBleGattEvent.Subscribed -> event.link
            is RappBleGattEvent.Routed -> event.link
            is RappBleGattEvent.Frame -> event.link
            is RappBleGattEvent.Closed -> event.link
            is RappBleGattEvent.Unsubscribed -> event.link
        }

    private fun closes(): List<RappBleLinkFailure> =
        events.filterIsInstance<RappBleGattEvent.Closed>().map { it.failure }

    private fun routedLink(): RappBleLink {
        subscribe()
        assertEquals(listOf(RappBleAttAnswer.SUCCESS), send(PREAMBLE))
        return linkOf(events.last { it is RappBleGattEvent.Routed })
    }

    /** What the central reassembles from the indications sent so far. */
    private fun indicated(): ByteArray? =
        RappBleSarReassembler().use { central ->
            port.indications.map { central.receive(it.second, capacity(), port.now) }.lastOrNull()
        }

    @Test
    fun aWriteBeforeTheSubscriptionIsRefusedWithoutAnAuthenticationError() {
        assertEquals(RappBleAttAnswer.WRITE_NOT_PERMITTED, send(PREAMBLE).single())
        assertTrue(admitted.isEmpty())
        assertTrue(events.isEmpty())
    }

    @Test
    fun aSubscriptionBelowTheMinimumMtuOpensAClosedLink() {
        assertEquals(RappBleAttAnswer.SUCCESS, subscribe(attMtu = SMALL_ATT_MTU))
        val subscribed = events.first() as RappBleGattEvent.Subscribed
        assertFalse(subscribed.accepted)
        assertEquals(SMALL_ATT_MTU, subscribed.attMtu)
        assertEquals(listOf(RappBleLinkFailure.ATT_MTU_TOO_SMALL), closes())
        assertEquals(
            RappBleAttAnswer.WRITE_NOT_PERMITTED,
            write(RappBleAttribute.CHANNEL, PREAMBLE.encodeToByteArray()),
        )
        assertTrue(admitted.isEmpty())
    }

    @Test
    fun aCentralThatNeverExchangedTheMtuHasTheDefaultAndIsRefused() {
        subscribe(attMtu = null)
        val subscribed = events.first() as RappBleGattEvent.Subscribed
        assertEquals(RappBleGattProfile.DEFAULT_ATT_MTU, subscribed.attMtu)
        assertEquals(listOf(RappBleLinkFailure.ATT_MTU_TOO_SMALL), closes())
    }

    @Test
    fun theMinimumMtuCarriesASarCapacity() {
        assertNotNull(RappBleSarCapacity.forAttMtu(ACCEPTED_ATT_MTU))
        assertNull(RappBleSarCapacity.forAttMtu(SMALL_ATT_MTU))
    }

    @Test
    fun theFirstFrameRoutesTheLinkAndLaterFramesGoToTheOwner() {
        val link = routedLink()
        assertEquals(listOf(PREAMBLE), admitted)
        assertTrue(send(FRAME).all { it == RappBleAttAnswer.SUCCESS })
        val frame = events.last() as RappBleGattEvent.Frame
        assertEquals(link, frame.link)
        assertEquals(FRAME, frame.frame.decodeToString())
        assertEquals(listOf(PREAMBLE), admitted)
    }

    @Test
    fun aFrameOfManyFragmentsReachesTheOwnerWhole() {
        routedLink()
        val answers = send(LONG_FRAME)
        assertTrue(answers.size > 1)
        assertTrue(answers.all { it == RappBleAttAnswer.SUCCESS })
        assertEquals(LONG_FRAME, (events.last() as RappBleGattEvent.Frame).frame.decodeToString())
    }

    @Test
    fun aRefusedPreambleClosesTheLinkUntilTheCentralUnsubscribes() {
        admitting = false
        subscribe()
        assertEquals(RappBleAttAnswer.WRITE_NOT_PERMITTED, send(PREAMBLE).single())
        assertEquals(listOf(RappBleLinkFailure.ROUTING_REFUSED), closes())
        assertEquals(RappBleAttAnswer.WRITE_NOT_PERMITTED, send(PREAMBLE).single())
        assertEquals(listOf(PREAMBLE), admitted)

        assertEquals(RappBleAttAnswer.SUCCESS, write(RappBleAttribute.CHANNEL_CCCD, RappBleCccd.DISABLED.wire()))
        assertTrue(events.last() is RappBleGattEvent.Unsubscribed)
        admitting = true
        subscribe()
        assertEquals(RappBleAttAnswer.SUCCESS, send(PREAMBLE).single())
        assertTrue(events.last() is RappBleGattEvent.Routed)
    }

    @Test
    fun aFragmentTheSarRulesRefuseClosesTheLink() {
        routedLink()
        assertEquals(
            RappBleAttAnswer.WRITE_NOT_PERMITTED,
            write(RappBleAttribute.CHANNEL, TRUNCATED_FRAGMENT.encodeToByteArray()),
        )
        assertEquals(listOf(RappBleLinkFailure.REASSEMBLY_FAILED), closes())
    }

    @Test
    fun aFrameThatDoesNotCompleteInFiveSecondsClosesTheLink() {
        routedLink()
        val fragments = rappBleSarSegment(LONG_FRAME.encodeToByteArray(), capacity())
        assertEquals(RappBleAttAnswer.SUCCESS, write(RappBleAttribute.CHANNEL, fragments.first()))
        port.advance(RappBleGattProfile.REASSEMBLY_TIMEOUT_MS)
        assertEquals(listOf(RappBleLinkFailure.REASSEMBLY_FAILED), closes())
        assertEquals(RappBleAttAnswer.WRITE_NOT_PERMITTED, write(RappBleAttribute.CHANNEL, fragments[1]))
    }

    @Test
    fun aWriteCommandOrAPreparedWriteIsAProtocolViolation() {
        routedLink()
        assertNull(write(RappBleAttribute.CHANNEL, FRAME.encodeToByteArray(), responseNeeded = false))
        assertEquals(listOf(RappBleLinkFailure.PROTOCOL_VIOLATION), closes())

        events.clear()
        write(RappBleAttribute.CHANNEL_CCCD, RappBleCccd.DISABLED.wire())
        routedLink()
        assertEquals(
            RappBleAttAnswer.WRITE_NOT_PERMITTED,
            write(RappBleAttribute.CHANNEL, FRAME.encodeToByteArray(), whole = false),
        )
        assertEquals(listOf(RappBleLinkFailure.PROTOCOL_VIOLATION), closes())
    }

    @Test
    fun onlyIndicationsOrNothingConfigureTheChannel() {
        val notifications = RappBleCccd.DISABLED.wire().also { it[LOW_OCTET] = (1 shl NOTIFICATIONS_BIT).toByte() }
        assertNull(RappBleCccd.of(notifications))
        assertEquals(RappBleAttAnswer.WRITE_NOT_PERMITTED, write(RappBleAttribute.CHANNEL_CCCD, notifications))
        assertEquals(RappBleAttAnswer.WRITE_NOT_PERMITTED, write(RappBleAttribute.CHANNEL_CCCD, null))
        assertTrue(events.isEmpty())
        assertEquals(RappBleCccd.INDICATIONS, RappBleCccd.of(RappBleCccd.INDICATIONS.wire()))
        assertEquals(RappBleCccd.DISABLED, RappBleCccd.of(RappBleCccd.DISABLED.wire()))
    }

    @Test
    fun readsAnswerTheConfigurationAndRefuseEverythingElse() {
        fun read(attribute: RappBleAttribute): Pair<RappBleAttAnswer, ByteArray?> {
            var answer: Pair<RappBleAttAnswer, ByteArray?>? = null
            links.read(RappBleRead(CENTRAL, attribute, NO_OFFSET) { status, value -> answer = status to value })
            return checkNotNull(answer)
        }
        assertArrayEquals(RappBleCccd.DISABLED.wire(), read(RappBleAttribute.CHANNEL_CCCD).second)
        subscribe()
        assertArrayEquals(RappBleCccd.INDICATIONS.wire(), read(RappBleAttribute.CHANNEL_CCCD).second)
        assertEquals(RappBleAttAnswer.READ_NOT_PERMITTED, read(RappBleAttribute.BOOTSTRAP).first)
        assertEquals(RappBleAttAnswer.READ_NOT_PERMITTED, read(RappBleAttribute.CHANNEL).first)
        assertEquals(RappBleAttAnswer.WRITE_NOT_PERMITTED, write(RappBleAttribute.BOOTSTRAP, FRAME.encodeToByteArray()))
    }

    @Test
    fun aFrameIsIndicatedOneFragmentAtATime() {
        val link = routedLink()
        links.send(link, LONG_FRAME.encodeToByteArray())
        assertEquals(1, port.indications.size)
        val fragments = rappBleSarSegment(LONG_FRAME.encodeToByteArray(), capacity()).size
        repeat(fragments - 1) { links.notificationSent(CENTRAL, delivered = true) }
        assertEquals(fragments, port.indications.size)
        assertEquals(LONG_FRAME, indicated()?.decodeToString())
    }

    @Test
    fun nothingIsIndicatedOnALinkThatHasNotRouted() {
        subscribe()
        val link = linkOf(events.single())
        links.send(link, FRAME.encodeToByteArray())
        assertTrue(port.indications.isEmpty())
    }

    @Test
    fun theOwnersCloseIndicatesWhatWasQueuedThenEnds() {
        val link = routedLink()
        links.send(link, LONG_FRAME.encodeToByteArray())
        links.close(link)
        assertTrue(closes().isEmpty())
        assertEquals(RappBleAttAnswer.WRITE_NOT_PERMITTED, send(FRAME).first())
        while (closes().isEmpty()) links.notificationSent(CENTRAL, delivered = true)
        assertEquals(listOf(RappBleLinkFailure.CANCELLED), closes())
        assertEquals(LONG_FRAME, indicated()?.decodeToString())
    }

    @Test
    fun theOwnersCloseEndsOnceTheDrainLimitPasses() {
        val link = routedLink()
        links.send(link, LONG_FRAME.encodeToByteArray())
        links.close(link)
        port.advance(RappBleGattProfile.CLOSE_DRAIN_LIMIT_MS)
        assertEquals(listOf(RappBleLinkFailure.CANCELLED), closes())
    }

    @Test
    fun anIndicationThatFailsClosesTheLink() {
        val link = routedLink()
        links.send(link, LONG_FRAME.encodeToByteArray())
        links.notificationSent(CENTRAL, delivered = false)
        assertEquals(listOf(RappBleLinkFailure.INDICATION_FAILED), closes())

        events.clear()
        write(RappBleAttribute.CHANNEL_CCCD, RappBleCccd.DISABLED.wire())
        port.refuseIndications = true
        links.send(routedLink(), FRAME.encodeToByteArray())
        assertEquals(listOf(RappBleLinkFailure.INDICATION_FAILED), closes())
    }

    @Test
    fun eachCentralHasItsOwnLink() {
        val first = routedLink()
        subscribe(OTHER_CENTRAL)
        val second = linkOf(events.last())
        assertFalse(first == second)
        admitting = false
        assertEquals(RappBleAttAnswer.WRITE_NOT_PERMITTED, send(PREAMBLE, OTHER_CENTRAL).single())
        assertEquals(listOf(RappBleLinkFailure.ROUTING_REFUSED), closes())
        assertTrue(send(FRAME).all { it == RappBleAttAnswer.SUCCESS })
        assertEquals(first, linkOf(events.last()))
    }

    @Test
    fun aDisconnectEndsTheLinkAndForgetsTheMtu() {
        routedLink()
        links.disconnected(CENTRAL)
        assertEquals(listOf(RappBleLinkFailure.DISCONNECTED), closes())
        events.clear()
        subscribe(attMtu = null)
        assertEquals(listOf(RappBleLinkFailure.ATT_MTU_TOO_SMALL), closes())
    }

    @Test
    fun bluetoothTurningOffEndsEveryLink() {
        routedLink()
        subscribe(OTHER_CENTRAL)
        links.radioDown()
        assertEquals(
            listOf(RappBleLinkFailure.BLUETOOTH_UNAVAILABLE, RappBleLinkFailure.BLUETOOTH_UNAVAILABLE),
            closes(),
        )
    }

    @Test
    fun aShutdownLetsQueuedFramesOutThenRefusesNewLinks() {
        val link = routedLink()
        links.send(link, LONG_FRAME.encodeToByteArray())
        var done = false
        links.shutdown { done = true }
        assertFalse(done)
        assertTrue(links.isFinished)
        while (!done) links.notificationSent(CENTRAL, delivered = true)
        assertEquals(LONG_FRAME, indicated()?.decodeToString())
        assertEquals(RappBleAttAnswer.WRITE_NOT_PERMITTED, subscribe(OTHER_CENTRAL))
    }

    @Test
    fun aShutdownWithNothingQueuedCompletesAtOnce() {
        routedLink()
        var done = false
        links.shutdown { done = true }
        assertTrue(done)
        assertEquals(listOf(RappBleLinkFailure.CANCELLED), closes())
    }
}
