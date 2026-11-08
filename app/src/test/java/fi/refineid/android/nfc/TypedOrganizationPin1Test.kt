// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.nfc

import fi.refineid.android.core.PIN1_MINIMUM_LENGTH
import fi.refineid.android.core.Pin1Submission
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class TypedOrganizationPin1Test {
    private var clock = 0L
    private val typed = TypedOrganizationPin1 { clock }

    @Test
    fun aTypedPinWaitsForTheNextTap() {
        typed.hold(Pin1Submission.from(SYNTHETIC_PIN))
        clock = NfcCardWait.LIMIT_MILLISECONDS
        val taken = typed.take()
        assertArrayEquals(SYNTHETIC_PIN.toByteArray(Charsets.US_ASCII), taken?.copyBytes())
        taken?.close()
        assertNull(typed.take())
    }

    @Test
    fun aPinPastTheWaitIsZeroedAndNotHandedOver() {
        val pin1 = Pin1Submission.from(SYNTHETIC_PIN)
        typed.hold(pin1)
        clock = NfcCardWait.LIMIT_MILLISECONDS + 1
        assertNull(typed.take())
        assertThrows(IllegalStateException::class.java) { pin1.copyBytes() }
    }

    @Test
    fun aNewerPinReplacesAndZeroesTheOlder() {
        val older = Pin1Submission.from(SYNTHETIC_PIN)
        typed.hold(older)
        typed.hold(Pin1Submission.from(OTHER_PIN))
        assertThrows(IllegalStateException::class.java) { older.copyBytes() }
        val taken = typed.take()
        assertArrayEquals(OTHER_PIN.toByteArray(Charsets.US_ASCII), taken?.copyBytes())
        taken?.close()
    }

    @Test
    fun droppingZeroesTheWaitingPin() {
        val pin1 = Pin1Submission.from(SYNTHETIC_PIN)
        typed.hold(pin1)
        typed.drop()
        assertThrows(IllegalStateException::class.java) { pin1.copyBytes() }
        assertNull(typed.take())
    }

    private companion object {
        /** Synthetic digit strings of the shortest PIN 1 length. */
        val SYNTHETIC_PIN = CharArray(PIN1_MINIMUM_LENGTH) { '0' }.concatToString()
        val OTHER_PIN = CharArray(PIN1_MINIMUM_LENGTH) { '1' }.concatToString()
    }
}
