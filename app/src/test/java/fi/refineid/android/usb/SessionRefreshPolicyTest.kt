package fi.refineid.android.usb

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SessionRefreshPolicyTest {
    @Test
    fun healthySessionOnTheSameDeviceIsKept() {
        for (status in KEEPABLE_STATUSES) {
            assertTrue(
                "status $status must keep the session",
                shouldKeepSessionOnRefresh(
                    previousDeviceId = SELECTED_DEVICE_ID,
                    deviceId = SELECTED_DEVICE_ID,
                    status = status,
                    cardPresence = CardPresence.PRESENT,
                    hasSession = true,
                ),
            )
        }
    }

    @Test
    fun missingSessionReopens() {
        assertFalse(
            shouldKeepSessionOnRefresh(
                previousDeviceId = SELECTED_DEVICE_ID,
                deviceId = SELECTED_DEVICE_ID,
                status = ReaderConnectionStatus.READY,
                cardPresence = CardPresence.PRESENT,
                hasSession = false,
            ),
        )
    }

    @Test
    fun changedDeviceReopens() {
        assertFalse(
            shouldKeepSessionOnRefresh(
                previousDeviceId = SELECTED_DEVICE_ID,
                deviceId = OTHER_DEVICE_ID,
                status = ReaderConnectionStatus.READY,
                cardPresence = CardPresence.PRESENT,
                hasSession = true,
            ),
        )
    }

    @Test
    fun firstSelectionReopens() {
        assertFalse(
            shouldKeepSessionOnRefresh(
                previousDeviceId = null,
                deviceId = SELECTED_DEVICE_ID,
                status = ReaderConnectionStatus.READY,
                cardPresence = CardPresence.PRESENT,
                hasSession = true,
            ),
        )
    }

    @Test
    fun checkingReopens() {
        assertFalse(
            shouldKeepSessionOnRefresh(
                previousDeviceId = SELECTED_DEVICE_ID,
                deviceId = SELECTED_DEVICE_ID,
                status = ReaderConnectionStatus.CHECKING,
                cardPresence = CardPresence.PRESENT,
                hasSession = true,
            ),
        )
    }

    @Test
    fun errorStatusesReopen() {
        for (status in REOPEN_STATUSES) {
            assertFalse(
                "status $status must reopen",
                shouldKeepSessionOnRefresh(
                    previousDeviceId = SELECTED_DEVICE_ID,
                    deviceId = SELECTED_DEVICE_ID,
                    status = status,
                    cardPresence = CardPresence.PRESENT,
                    hasSession = true,
                ),
            )
        }
    }

    @Test
    fun removedCardReopens() {
        assertFalse(
            shouldKeepSessionOnRefresh(
                previousDeviceId = SELECTED_DEVICE_ID,
                deviceId = SELECTED_DEVICE_ID,
                status = ReaderConnectionStatus.READY,
                cardPresence = CardPresence.NOT_PRESENT,
                hasSession = true,
            ),
        )
    }

    @Test
    fun unknownPresenceReopens() {
        assertFalse(
            shouldKeepSessionOnRefresh(
                previousDeviceId = SELECTED_DEVICE_ID,
                deviceId = SELECTED_DEVICE_ID,
                status = ReaderConnectionStatus.READY,
                cardPresence = null,
                hasSession = true,
            ),
        )
    }

    private companion object {
        const val SELECTED_DEVICE_ID = 7
        const val OTHER_DEVICE_ID = 9
        val KEEPABLE_STATUSES =
            listOf(
                ReaderConnectionStatus.READY,
                ReaderConnectionStatus.ACTIVATION_REQUIRED,
                ReaderConnectionStatus.ACCESS_NUMBER_REQUIRED,
                ReaderConnectionStatus.WRONG_ACCESS_NUMBER,
            )
        val REOPEN_STATUSES =
            listOf(
                ReaderConnectionStatus.NOT_CONNECTED,
                ReaderConnectionStatus.PERMISSION_REQUIRED,
                ReaderConnectionStatus.PERMISSION_REQUEST_FAILED,
                ReaderConnectionStatus.CARD_ERROR,
                ReaderConnectionStatus.TRANSPORT_ERROR,
            )
    }
}
