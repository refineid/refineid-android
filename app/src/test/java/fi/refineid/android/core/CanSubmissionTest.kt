package fi.refineid.android.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class CanSubmissionTest {
    @Test
    fun acceptsOnlyDigitEntriesUpToTheCanLength() {
        assertTrue(CanSubmission.acceptsEntry(""))
        assertTrue(CanSubmission.acceptsEntry("123"))
        assertTrue(CanSubmission.acceptsEntry(SYNTHETIC_CAN))
        assertFalse(CanSubmission.acceptsEntry("1234567"))
        assertFalse(CanSubmission.acceptsEntry("12345A"))
    }

    @Test
    fun isCompleteOnlyAtExactlySixDigits() {
        assertFalse(CanSubmission.isComplete("12345"))
        assertTrue(CanSubmission.isComplete(SYNTHETIC_CAN))
        assertFalse(CanSubmission.isComplete("1234567"))
    }

    @Test
    fun transfersOwnershipExactlyOnce() {
        val submission = CanSubmission.from(SYNTHETIC_CAN)

        val bytes = submission.transfer()

        assertArrayEquals(SYNTHETIC_CAN.map { it.code.toByte() }.toByteArray(), bytes)
        assertThrows(IllegalStateException::class.java) {
            submission.transfer()
        }
        bytes.fill(0)
    }

    @Test
    fun workerCopySurvivesCancellationOfOriginalSubmission() {
        val submission = CanSubmission.from(SYNTHETIC_CAN)
        val workerCopy = submission.copy()
        submission.close()
        val bytes = workerCopy.transfer()
        try {
            assertArrayEquals(SYNTHETIC_CAN.map { it.code.toByte() }.toByteArray(), bytes)
        } finally {
            bytes.fill(0)
            workerCopy.close()
        }
    }

    @Test
    fun closingWithoutTransferZeroizesAndInvalidates() {
        val submission = CanSubmission.from(SYNTHETIC_CAN)

        submission.close()

        assertThrows(IllegalStateException::class.java) {
            submission.transfer()
        }
    }

    @Test
    fun redactsItsStringForm() {
        assertFalse(CanSubmission.from(SYNTHETIC_CAN).toString().contains(SYNTHETIC_CAN))
    }

    private companion object {
        // A syntactically valid but meaningless CAN for shape tests
        // only; never a real card value.
        const val SYNTHETIC_CAN = "000000"
    }
}
