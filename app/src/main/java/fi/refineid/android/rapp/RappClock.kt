// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import android.os.SystemClock

/**
 * Wall and monotonic clocks in the millisecond units RAPP uses, mirroring the
 * Apple `RappPlatformClock`. Every timestamp handed to one bridge must come
 * from the same clock domain, so call sites use these two sources and nothing
 * else.
 */
internal object RappClock {
    /** Milliseconds since the Unix epoch; moves with wall-clock changes. */
    fun wallMs(): ULong = System.currentTimeMillis().toULong()

    /**
     * Milliseconds of the continuous clock (RAPP v26.10.29 section 8.1 item
     * 2): never moves backwards and keeps counting through device sleep and
     * process suspension, so offer, liveness and operation deadlines track
     * real elapsed time. `SystemClock.uptimeMillis` pauses in deep sleep and
     * is never used for a deadline.
     */
    fun monotonicMs(): ULong = SystemClock.elapsedRealtime().toULong()
}
