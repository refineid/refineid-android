package fi.refineid.android.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class SigningTransportLatchTest {
    @Test
    fun emptyLatchPrefersUsb() {
        assertEquals(
            SigningTransport.USB,
            nextSigningTransport(
                current = null,
                usbPresent = true,
                nfcPresent = true,
            ),
        )
    }

    @Test
    fun emptyLatchTakesNfcWhenUsbIsGone() {
        assertEquals(
            SigningTransport.NFC,
            nextSigningTransport(
                current = null,
                usbPresent = false,
                nfcPresent = true,
            ),
        )
    }

    @Test
    fun emptyLatchStaysEmptyWithoutTransports() {
        assertNull(
            nextSigningTransport(
                current = null,
                usbPresent = false,
                nfcPresent = false,
            ),
        )
    }

    @Test
    fun heldUsbLatchSurvivesTransientUnreadiness() {
        assertEquals(
            SigningTransport.USB,
            nextSigningTransport(
                current = SigningTransport.USB,
                usbPresent = true,
                nfcPresent = true,
            ),
        )
    }

    @Test
    fun heldNfcLatchIsNotYankedBackToUsb() {
        assertEquals(
            SigningTransport.NFC,
            nextSigningTransport(
                current = SigningTransport.NFC,
                usbPresent = true,
                nfcPresent = true,
            ),
        )
    }

    @Test
    fun goneUsbFallsBackToNfc() {
        assertEquals(
            SigningTransport.NFC,
            nextSigningTransport(
                current = SigningTransport.USB,
                usbPresent = false,
                nfcPresent = true,
            ),
        )
    }

    @Test
    fun goneUsbWithoutFallbackReleasesTheLatch() {
        assertNull(
            nextSigningTransport(
                current = SigningTransport.USB,
                usbPresent = false,
                nfcPresent = false,
            ),
        )
    }

    @Test
    fun goneNfcFallsBackToUsb() {
        assertEquals(
            SigningTransport.USB,
            nextSigningTransport(
                current = SigningTransport.NFC,
                usbPresent = true,
                nfcPresent = false,
            ),
        )
    }

    @Test
    fun goneNfcWithoutFallbackReleasesTheLatch() {
        assertNull(
            nextSigningTransport(
                current = SigningTransport.NFC,
                usbPresent = false,
                nfcPresent = false,
            ),
        )
    }
}
