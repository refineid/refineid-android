package fi.refineid.android.usb

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ReaderCardPresenceWatchTest {
    @Test
    fun removingTheCardEndsItsPresence() {
        val watch = ReaderCardPresenceWatch()
        assertFalse(watch.presenceEnded(PRESENT))
        assertTrue(watch.presenceEnded(REMOVED))
    }

    @Test
    fun disconnectingTheReaderEndsThePresence() {
        val watch = ReaderCardPresenceWatch()
        assertFalse(watch.presenceEnded(PRESENT))
        assertTrue(watch.presenceEnded(UsbReaderSnapshot()))
    }

    @Test
    fun aProbeThatSaysNothingAboutTheCardKeepsIt() {
        val watch = ReaderCardPresenceWatch()
        assertFalse(watch.presenceEnded(PRESENT))
        assertFalse(watch.presenceEnded(UsbReaderSnapshot(status = ReaderConnectionStatus.CHECKING)))
        assertFalse(watch.presenceEnded(UsbReaderSnapshot(status = ReaderConnectionStatus.TRANSPORT_ERROR)))
        assertTrue(watch.presenceEnded(REMOVED))
    }

    @Test
    fun anEndIsReportedOnce() {
        val watch = ReaderCardPresenceWatch()
        watch.presenceEnded(PRESENT)
        assertTrue(watch.presenceEnded(REMOVED))
        assertFalse(watch.presenceEnded(UsbReaderSnapshot()))
    }

    @Test
    fun noCardMeansNothingEnds() {
        val watch = ReaderCardPresenceWatch()
        assertFalse(watch.presenceEnded(UsbReaderSnapshot()))
        assertFalse(watch.presenceEnded(REMOVED))
    }

    @Test
    fun aReinsertedCardStartsANewPresence() {
        val watch = ReaderCardPresenceWatch()
        watch.presenceEnded(PRESENT)
        watch.presenceEnded(REMOVED)
        assertFalse(watch.presenceEnded(PRESENT))
        assertTrue(watch.presenceEnded(REMOVED))
    }

    private companion object {
        val PRESENT =
            UsbReaderSnapshot(
                status = ReaderConnectionStatus.READY,
                cardPresence = CardPresence.PRESENT,
            )
        val REMOVED =
            UsbReaderSnapshot(
                status = ReaderConnectionStatus.READY,
                cardPresence = CardPresence.NOT_PRESENT,
            )
    }
}
