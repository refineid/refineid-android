// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.browser

import java.util.Locale

/**
 * The addresses the in-app browser visited while this process lives, newest
 * first, for completing what the holder types. Nothing is written anywhere:
 * the history ends with the process. An address is kept without its query
 * and fragment, so tokens a login passes in them are never kept or offered.
 */
internal class BrowserSessionHistory(
    private val entryLimit: Int = ENTRY_LIMIT,
) {
    private val entries = ArrayDeque<String>()

    /** Records a page the browser reached at [url]; non-HTTPS addresses are ignored. */
    @Synchronized
    fun record(url: String) {
        val entry = entryOf(url) ?: return
        entries.remove(entry)
        entries.addFirst(entry)
        while (entries.size > entryLimit) {
            entries.removeLast()
        }
    }

    /**
     * Up to [limit] visited addresses matching [typed], newest first, those
     * whose host starts with it before those that only contain it. An empty
     * entry, or one that already equals a visited address, offers nothing.
     */
    @Synchronized
    fun suggestions(
        typed: String,
        limit: Int = SUGGESTION_LIMIT,
    ): List<String> {
        val query = withoutScheme(typed.trim()).lowercase(Locale.ROOT)
        if (query.isEmpty()) return emptyList()
        val matching = entries.filter { withoutScheme(it).lowercase(Locale.ROOT).contains(query) }
        if (matching.any { withoutScheme(it).lowercase(Locale.ROOT) == query }) return emptyList()
        val (prefixed, contained) = matching.partition { readable(it).lowercase(Locale.ROOT).startsWith(query) }
        return (prefixed + contained).take(limit)
    }

    /** Forgets every visited address. */
    @Synchronized
    fun clear() {
        entries.clear()
    }

    internal companion object {
        /** How many addresses one process keeps. */
        const val ENTRY_LIMIT = 200

        /** How many suggestions the address bar shows at once. */
        const val SUGGESTION_LIMIT = 5

        /** The history of this process, shared by every browser it opens. */
        val process = BrowserSessionHistory()

        private const val HTTPS_PREFIX = "https://"
        private const val WWW_PREFIX = "www."
        private const val QUERY = '?'
        private const val FRAGMENT = '#'

        /** [url] without its query and fragment, or null when it is not HTTPS with a host. */
        fun entryOf(url: String): String? {
            if (!url.startsWith(HTTPS_PREFIX, ignoreCase = true)) return null
            val entry = url.substringBefore(FRAGMENT).substringBefore(QUERY)
            return entry.takeIf { withoutScheme(it).isNotEmpty() }
        }

        /** [url] as the holder reads it: without the scheme. */
        fun readable(url: String): String {
            val address = withoutScheme(url)
            return if (address.startsWith(WWW_PREFIX, ignoreCase = true)) address.drop(WWW_PREFIX.length) else address
        }

        private fun withoutScheme(url: String): String =
            if (url.startsWith(HTTPS_PREFIX, ignoreCase = true)) url.drop(HTTPS_PREFIX.length) else url
    }
}
