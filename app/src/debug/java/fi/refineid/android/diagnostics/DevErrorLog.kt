// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.diagnostics

import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * The debug build's error sink: every failure path reports here through
 * [AppTrace], and each entry goes to logcat under [TAG] and to the list the
 * error display shows.
 *
 * Debug source set only; a release build has no such class. An entry names
 * the event and the case or type that caused it, never a value read from
 * the card, the network, the device or the user.
 */
internal object DevErrorLog {
    /** The logcat tag: `adb logcat -s RefineIDErrors` shows every entry. */
    const val TAG = "RefineIDErrors"

    /** How many entries the list keeps; the oldest go first. */
    const val CAPACITY = 50

    /** The longest message kept, in characters. */
    const val MAXIMUM_MESSAGE_LENGTH = 240

    /** One reported error. */
    data class Entry(
        /** Tells two entries with the same text apart. */
        val serial: Long,
        /** When it was last reported. */
        val reportedAt: Instant,
        /** The event and its cause. */
        val message: String,
        /** How many times in a row it was reported. */
        val occurrences: Int = 1,
    ) {
        /** The message, with how many times in a row it came. */
        val text: String
            get() = if (occurrences > 1) "$message (x$occurrences)" else message
    }

    private val mutableEntries = MutableStateFlow<List<Entry>>(emptyList())
    private var reported = 0L

    /** Every entry held, newest first. */
    val entries: StateFlow<List<Entry>> = mutableEntries.asStateFlow()

    /** Records [event] with its [cause], a case or type name, and writes it to logcat. */
    fun report(
        event: String,
        cause: String? = null,
    ) {
        val message = sanitized(if (cause == null) event else "$event cause=$cause")
        try {
            Log.e(TAG, message)
        } catch (_: RuntimeException) {
            // Local JVM tests use the Android stub; a device implementation logs.
        }
        val entry =
            synchronized(this) {
                reported++
                Entry(reported, Instant.now(), message)
            }
        mutableEntries.update { held -> prepending(entry, held) }
    }

    /** Forgets every entry. */
    fun clear() {
        mutableEntries.value = emptyList()
    }

    /**
     * [held], newest first, with [entry] in front and cut to [CAPACITY]. An
     * error reported again straight after itself takes the place of the
     * earlier one and counts it, so a loop failing the same way on every pass
     * shows as one line.
     */
    fun prepending(
        entry: Entry,
        held: List<Entry>,
    ): List<Entry> {
        val newest = held.firstOrNull()
        val (added, rest) =
            if (newest != null && newest.message == entry.message) {
                entry.copy(occurrences = newest.occurrences + entry.occurrences) to held.drop(1)
            } else {
                entry to held
            }
        return (listOf(added) + rest).take(CAPACITY)
    }

    /** [held] as lines of text, oldest first, as a log reads; each line starts with its UTC time. */
    fun transcript(held: List<Entry>): String =
        held.asReversed().joinToString(separator = "\n") { entry ->
            TRANSCRIPT_TIME.format(entry.reportedAt) + " " + entry.text
        }

    /** [message] on one line and no longer than [MAXIMUM_MESSAGE_LENGTH]. */
    fun sanitized(message: String): String =
        message
            .map { if (it.isISOControl()) ' ' else it }
            .joinToString(separator = "")
            .take(MAXIMUM_MESSAGE_LENGTH)

    private val TRANSCRIPT_TIME: DateTimeFormatter =
        DateTimeFormatter.ISO_OFFSET_DATE_TIME.withZone(ZoneOffset.UTC)
}
