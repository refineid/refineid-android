package fi.refineid.android.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class AuthenticationPinCacheTest {
    @Test
    fun holdsAVerifiedPinForItsCardUntilCleared() {
        val cache = AuthenticationPinCache()
        assertFalse(cache.hasPin)
        cache.recordVerified(pinBytes(), retention(CARD_A))
        assertTrue(cache.hasPin)
        assertTrue(cache.holds(CARD_A))

        val held = cache.take(CARD_A)
        assertArrayEquals(PIN_BYTES, held?.copyBytes())
        held?.close()
        assertTrue("taking hands out a copy", cache.holds(CARD_A))

        cache.clear()
        assertFalse(cache.hasPin)
        assertNull(cache.take(CARD_A))
    }

    @Test
    fun aPinHeldForOneCardIsNeverHandedOutForAnother() {
        val cache = AuthenticationPinCache()
        cache.recordVerified(pinBytes(), retention(CARD_A))
        val pin = Pin1Submission.fromOwnedBytes(pinBytes())

        assertFalse(cache.holds(CARD_B))
        assertFalse(cache.isVerified(pin, CARD_B))
        assertTrue(cache.isVerified(pin, CARD_A))
        assertNull(cache.take(CARD_B))

        assertFalse("another card's request destroys the held PIN", cache.hasPin)
        assertNull(cache.take(CARD_A))
        pin.close()
    }

    @Test
    fun onlyAPristineCounterOnAKnownCardGivesLeaveToHold() {
        assertNotNull(Pin1Retention.of(CARD_A, FINEID_PIN_TRY_LIMIT))
        assertNull(Pin1Retention.of(CARD_A, ONE_ATTEMPT_SPENT))
        assertNull(Pin1Retention.of(CARD_A, null))
        assertNull(Pin1Retention.of(null, FINEID_PIN_TRY_LIMIT))
    }

    @Test
    fun aCardIsNamedByItsCertificate() {
        assertNull(AuthenticationCardIdentity.of(ByteArray(0)))
        assertEquals(CARD_A, AuthenticationCardIdentity.of(CERTIFICATE_A.encodeToByteArray()))
        assertNotEquals(CARD_A, CARD_B)
    }

    @Test
    fun refusesAValueTheCardRejected() {
        val cache = AuthenticationPinCache()

        assertFalse(cache.isRejected(pinBytes()))
        cache.recordRejected(pinBytes())
        assertTrue(cache.isRejected(pinBytes()))
    }

    @Test
    fun rejectingTheHeldValueDropsIt() {
        val cache = AuthenticationPinCache()
        cache.recordVerified(pinBytes(), retention(CARD_A))

        cache.recordRejected(pinBytes())

        assertNull(cache.take(CARD_A))
        assertTrue(cache.isRejected(pinBytes()))
    }

    @Test
    fun rejectingPinRetainsRejectionStatusAcrossClear() {
        val cache = AuthenticationPinCache()
        cache.recordRejected(pinBytes())
        assertTrue(cache.isRejected(pinBytes()))

        cache.clear()
        assertTrue(cache.isRejected(pinBytes()))
    }

    @Test
    fun takeDoesNotLeakOrKeepDanglingReferencesAfterClose() {
        val cache = AuthenticationPinCache()
        cache.recordVerified(pinBytes(), retention(CARD_A))

        val entry = cache.take(CARD_A)
        val copy = entry?.copyBytes()
        assertArrayEquals(PIN_BYTES, copy)
        entry?.close()
        assertThrows(IllegalStateException::class.java) { entry?.copyBytes() }
    }

    @Test
    fun independentOwnershipPreservesCachedPinWhenSecondaryConsumerZeroizes() {
        val cache = AuthenticationPinCache()
        val submission = Pin1Submission.fromOwnedBytes(pinBytes())

        val cachePin = submission.copyBytes()
        cache.recordVerified(cachePin, retention(CARD_A))

        val consumerPin = submission.copyBytes()
        // Simulate a consumer taking ownership of its copy and zeroizing it
        consumerPin.fill(CLEARED_BYTE)

        val held = cache.take(CARD_A)
        assertNotNull(held)
        assertArrayEquals(PIN_BYTES, held?.copyBytes())
        held?.close()
        submission.close()
    }

    @Test
    fun staleSuccessCannotRestoreClearedCache() {
        val cache = AuthenticationPinCache()
        val generation = cache.generation
        cache.clear()
        val stale = pinBytes()
        assertFalse(cache.recordVerified(stale, retention(CARD_A), generation))
        assertTrue(stale.all { it == CLEARED_BYTE })
        assertFalse(cache.hasPin)
    }

    private fun pinBytes(): ByteArray = PIN_BYTES.copyOf()

    private fun retention(card: AuthenticationCardIdentity): Pin1Retention =
        checkNotNull(Pin1Retention.of(card, FINEID_PIN_TRY_LIMIT))

    private companion object {
        const val CLEARED_BYTE: Byte = 0
        const val ONE_ATTEMPT_SPENT = FINEID_PIN_TRY_LIMIT - 1
        const val CERTIFICATE_A = "synthetic authentication certificate of card A"
        const val CERTIFICATE_B = "synthetic authentication certificate of card B"

        // Synthetic digits for shape tests only; never a real PIN.
        val PIN_BYTES = "0000".encodeToByteArray()
        val CARD_A = checkNotNull(AuthenticationCardIdentity.of(CERTIFICATE_A.encodeToByteArray()))
        val CARD_B = checkNotNull(AuthenticationCardIdentity.of(CERTIFICATE_B.encodeToByteArray()))
    }
}
