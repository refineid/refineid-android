package fi.refineid.android.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AuthenticationPinCacheTest {
    @Test
    fun holdsAVerifiedPinUntilTheIdleWindowLapses() {
        var now = 0L
        val cache = AuthenticationPinCache(lifetimeMillis = WINDOW, clock = { now })

        cache.recordVerified(pinBytes())

        now = WINDOW - 1
        val early = cache.take()
        assertArrayEquals(PIN_BYTES, early?.copyBytes())
        early?.close()

        now += WINDOW - 1
        assertTrue("use refreshes the window", cache.take() != null)

        now += WINDOW
        assertNull("an idle window past the last use expires", cache.take())
    }

    @Test
    fun refusesAValueTheCardRejected() {
        val cache = AuthenticationPinCache(lifetimeMillis = WINDOW, clock = { 0L })

        assertFalse(cache.isRejected(pinBytes()))
        cache.recordRejected(pinBytes())
        assertTrue(cache.isRejected(pinBytes()))
    }

    @Test
    fun rejectingTheHeldValueDropsIt() {
        val cache = AuthenticationPinCache(lifetimeMillis = WINDOW, clock = { 0L })
        cache.recordVerified(pinBytes())

        cache.recordRejected(pinBytes())

        assertNull(cache.take())
        assertTrue(cache.isRejected(pinBytes()))
    }

    @Test
    fun clearForgetsTheHeldValue() {
        val cache = AuthenticationPinCache(lifetimeMillis = WINDOW, clock = { 0L })
        cache.recordVerified(pinBytes())

        cache.clear()

        assertNull(cache.take())
        assertFalse(cache.hasPin)
    }

    @Test
    fun rejectingPinRetainsRejectionStatusAcrossClear() {
        val cache = AuthenticationPinCache(lifetimeMillis = WINDOW, clock = { 0L })
        cache.recordRejected(pinBytes())
        assertTrue(cache.isRejected(pinBytes()))

        cache.clear()
        assertTrue(cache.isRejected(pinBytes()))
    }

    @Test
    fun takeDoesNotLeakOrKeepDanglingReferencesAfterClose() {
        val cache = AuthenticationPinCache(lifetimeMillis = WINDOW, clock = { 0L })
        cache.recordVerified(pinBytes())

        val entry = cache.take()
        val copy = entry?.copyBytes()
        assertArrayEquals(PIN_BYTES, copy)
        entry?.close()
        assertNull(entry?.copyBytes())
    }

    @Test
    fun defaultCacheHoldsVerifiedPinIndefinitely() {
        val cache = AuthenticationPinCache()
        assertFalse(cache.hasPin)
        cache.recordVerified(pinBytes())
        assertTrue(cache.hasPin)

        val held = cache.take()
        assertArrayEquals(PIN_BYTES, held?.copyBytes())
        held?.close()
        assertTrue(cache.hasPin)

        cache.clear()
        assertFalse(cache.hasPin)
        assertNull(cache.take())
    }

    private fun pinBytes(): ByteArray = PIN_BYTES.copyOf()

    private companion object {
        const val WINDOW = 1_000L

        // Synthetic digits for shape tests only; never a real PIN.
        val PIN_BYTES = "0000".encodeToByteArray()
    }
}
