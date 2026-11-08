// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

/**
 * A baseline level a completion reached before it stopped short of
 * B-LTA: ETSI EN 319 142-1 clause 6 for PAdES, ETSI EN 319 132-1
 * clause 6 for XAdES. Both standards name the levels alike.
 */
internal enum class BaselineLevel(
    /** The level's name as both standards spell it. */
    val label: String,
) {
    /** The card signature with its certificate, no timestamp. */
    B_B("B-B"),

    /** B-B with a signature timestamp. */
    B_T("B-T"),

    /** B-T with the certificate and revocation values, no archive timestamp. */
    B_LT("B-LT"),
}

/**
 * What a completion does when it cannot reach B-LTA, for every
 * signature format. The build fixes it at compile time through
 * [forBuild]; nothing at run time selects it.
 */
internal enum class ArchivalLevelPolicy {
    /** Only a B-LTA signature leaves the completion; anything less is discarded. */
    LONG_TERM_ONLY,

    /** The highest level reached is handed out, named by its level, for development use. */
    HIGHEST_REACHED,
    ;

    companion object {
        /** A release build makes only B-LTA signatures; a debug build keeps what it reached. */
        fun forBuild(isDebugBuild: Boolean): ArchivalLevelPolicy =
            if (isDebugBuild) {
                HIGHEST_REACHED
            } else {
                LONG_TERM_ONLY
            }
    }
}
