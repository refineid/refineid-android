// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.diagnostics

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant
import java.util.concurrent.CountDownLatch
import kotlin.concurrent.thread

class DevErrorLogTest {
    private companion object {
        const val EVENT = "rapp:dial-refused"
        const val OTHER_EVENT = "nfc:session-open-failed"
        const val CAUSE = "STREAM BUSY"
        const val REPEATS = 3

        /** How many entries more than the list holds are reported. */
        const val OVERFLOW = 2
        const val CONTROL_SEPARATED = "first\nsecond\tthird"
        const val SPACE_SEPARATED = "first second third"
        val REPORTED_AT: Instant = Instant.EPOCH

        /** Threads reporting at once, and how many distinct errors each reports; together within the capacity. */
        const val REPORTERS = 8
        const val REPORTS_EACH = 6
    }

    @After
    fun tearDown() {
        DevErrorLog.clear()
    }

    private fun entry(
        serial: Long,
        message: String,
    ) = DevErrorLog.Entry(serial, REPORTED_AT, message)

    @Test
    fun reportsAreListedNewestFirstWithTheirCause() {
        DevErrorLog.report(EVENT, CAUSE)
        DevErrorLog.report(OTHER_EVENT)

        assertEquals(
            listOf(OTHER_EVENT, "$EVENT cause=$CAUSE"),
            DevErrorLog.entries.value.map { it.text },
        )
    }

    @Test
    fun anErrorRepeatedStraightAfterItselfFoldsIntoOneCountedEntry() {
        repeat(REPEATS) { DevErrorLog.report(EVENT) }
        DevErrorLog.report(OTHER_EVENT)
        DevErrorLog.report(EVENT)

        assertEquals(
            listOf(EVENT, OTHER_EVENT, "$EVENT (x$REPEATS)"),
            DevErrorLog.entries.value.map { it.text },
        )
    }

    @Test
    fun concurrentReportsAreListedInTheOrderTheyWereNumbered() {
        val start = CountDownLatch(1)
        val reporters =
            List(REPORTERS) { reporter ->
                thread {
                    start.await()
                    repeat(REPORTS_EACH) { report -> DevErrorLog.report("$EVENT-$reporter-$report") }
                }
            }
        start.countDown()
        reporters.forEach(Thread::join)

        val serials = DevErrorLog.entries.value.map { it.serial }
        assertEquals(REPORTERS * REPORTS_EACH, serials.size)
        assertEquals(serials.sortedDescending(), serials)
    }

    @Test
    fun theListKeepsTheNewestEntriesUpToItsCapacity() {
        val added = DevErrorLog.CAPACITY + OVERFLOW
        var held = emptyList<DevErrorLog.Entry>()
        repeat(added) { index ->
            held = DevErrorLog.prepending(entry(index.toLong(), EVENT + index), held)
        }

        assertEquals((OVERFLOW until added).reversed().map { EVENT + it }, held.map { it.message })
    }

    @Test
    fun aMessageIsOneLineNoLongerThanTheLimit() {
        assertEquals(SPACE_SEPARATED, DevErrorLog.sanitized(CONTROL_SEPARATED))
        val long = EVENT.repeat(DevErrorLog.MAXIMUM_MESSAGE_LENGTH)
        assertEquals(DevErrorLog.MAXIMUM_MESSAGE_LENGTH, DevErrorLog.sanitized(long).length)
    }

    @Test
    fun theTranscriptReadsOldestFirstWithTimes() {
        DevErrorLog.report(EVENT)
        DevErrorLog.report(OTHER_EVENT)

        val lines = DevErrorLog.transcript(DevErrorLog.entries.value).lines()

        assertEquals(listOf(EVENT, OTHER_EVENT), lines.map { it.substringAfter(' ') })
    }

    @Test
    fun clearingEmptiesTheList() {
        DevErrorLog.report(EVENT)
        DevErrorLog.clear()

        assertTrue(DevErrorLog.entries.value.isEmpty())
    }
}
