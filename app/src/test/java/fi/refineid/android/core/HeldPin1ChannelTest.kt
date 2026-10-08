package fi.refineid.android.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

internal class HeldPin1ChannelTest {
    @Test
    fun liveChannelVerifiesWithoutHandshake() {
        val channel = Channel(held = true, connected = true)
        val candidate = syntheticPin()
        assertEquals(Pin1VerificationResult.VERIFIED, verifyPin1OnHeldChannel(channel, candidate) { true })
        assertEquals(listOf(VERIFY), channel.steps)
        assertClosed(candidate)
    }

    @Test
    fun deadHeldChannelReleasesKeysBeforeReopening() {
        val channel = Channel(held = true, connected = false)
        assertEquals(Pin1VerificationResult.VERIFIED, verifyPin1OnHeldChannel(channel, syntheticPin()) { true })
        assertEquals(listOf(RELEASE, REOPEN, VERIFY), channel.steps)
        assertEquals(1, channel.releasedLiveKeys)
    }

    @Test
    fun supersededDuringHandshakeNeverPresentsPinAndReleasesChannel() {
        var generation = 0
        val channel = Channel(held = false, connected = false) { generation++ }
        val candidate = syntheticPin()
        val result = verifyPin1OnHeldChannel(channel, candidate) { generation == 0 }
        assertEquals(Pin1VerificationResult.CARD_UNAVAILABLE, result)
        assertEquals(listOf(RELEASE, REOPEN, RELEASE, CLOSE_FIELD), channel.steps)
        assertFalse(channel.held)
        assertFalse(channel.connected)
        assertClosed(candidate)
    }

    @Test
    fun supersededLiveChannelIsLeftToItsSuccessor() {
        val channel = Channel(held = true, connected = true)
        val candidate = syntheticPin()
        assertEquals(
            Pin1VerificationResult.CARD_UNAVAILABLE,
            verifyPin1OnHeldChannel(channel, candidate) { false },
        )
        assertTrue(channel.steps.isEmpty())
        assertTrue(channel.held)
        assertClosed(candidate)
    }

    @Test
    fun failedReopenNeverPresentsPin() {
        val channel = Channel(held = false, connected = false, reopenFailure = Pin1VerificationResult.SAFETY_REFUSED)
        val candidate = syntheticPin()
        assertEquals(
            Pin1VerificationResult.SAFETY_REFUSED,
            verifyPin1OnHeldChannel(channel, candidate) { true },
        )
        assertEquals(listOf(RELEASE, REOPEN), channel.steps)
        assertClosed(candidate)
    }

    /** Models held native keys and field state; [duringHandshake] runs inside PACE. */
    private class Channel(
        var held: Boolean,
        var connected: Boolean,
        private val reopenFailure: Pin1VerificationResult? = null,
        private val duringHandshake: () -> Unit = {},
    ) : HeldPin1Channel {
        val steps = mutableListOf<String>()
        var releasedLiveKeys = 0

        override val isLive: Boolean get() = held && connected

        override fun releaseHeld() {
            steps += RELEASE
            if (held) releasedLiveKeys++
            held = false
        }

        override fun reopen(): Pin1VerificationResult? {
            steps += REOPEN
            duringHandshake()
            if (reopenFailure != null) return reopenFailure
            connected = true
            held = true
            return null
        }

        override fun closeField() {
            steps += CLOSE_FIELD
            connected = false
        }

        override fun verify(pin1: Pin1Submission): Pin1VerificationResult {
            steps += VERIFY
            check(held && connected) { "VERIFY needs a live held channel" }
            pin1.close()
            return Pin1VerificationResult.VERIFIED
        }
    }

    private companion object {
        const val RELEASE = "release"
        const val REOPEN = "reopen"
        const val CLOSE_FIELD = "close-field"
        const val VERIFY = "verify"

        fun syntheticPin(): Pin1Submission =
            Pin1Submission.from(CharArray(PIN1_MINIMUM_LENGTH) { '0' }.concatToString())

        fun assertClosed(candidate: Pin1Submission) {
            assertTrue(runCatching { candidate.copyBytes() }.isFailure)
        }
    }
}
