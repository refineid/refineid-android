// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The requester's view of its paired custodian (RAPP v26.11.2 section
 * 4.7, `requester_view_of_custodian`): every state's transitions, the
 * redial window and the back-off.
 */
class RappViewOfCustodianTest {
    private companion object {
        const val NOW_MS = 10_000L

        /** The redial window of RAPP v26.11.2 section 8.3 item 3, in milliseconds. */
        const val SPEC_REDIAL_WINDOW_MS = 120_000L

        /** A millisecond inside or outside a bound. */
        const val BOUND_MARGIN_MS = 1L
        const val BEFORE_WINDOW_END_MS = NOW_MS + SPEC_REDIAL_WINDOW_MS - BOUND_MARGIN_MS
        const val WINDOW_END_MS = NOW_MS + SPEC_REDIAL_WINDOW_MS
        const val AFTER_WINDOW_END_MS = NOW_MS + SPEC_REDIAL_WINDOW_MS + BOUND_MARGIN_MS

        /** Redials observed while the back-off grows into its cap. */
        const val REDIALS_OBSERVED = 5
    }

    @Before
    fun setUp() {
        RappNativeTestLibrary.require()
    }

    private fun view() = RappViewOfCustodian()

    private fun connected(): RappViewOfCustodian {
        val view = view()
        view.event(RappViewOfCustodian.Event.RecordAppeared, NOW_MS)
        view.event(RappViewOfCustodian.Event.DialSucceeded, NOW_MS)
        return view
    }

    @Test
    fun theRedialWindowIsTheSpecBound() {
        assertEquals(SPEC_REDIAL_WINDOW_MS, RappViewOfCustodian.REDIAL_WINDOW_MS)
    }

    @Test
    fun anAppearanceOrAConsumerDialsFromIdle() {
        for (
        event in
        listOf(
            RappViewOfCustodian.Event.RecordAppeared,
            RappViewOfCustodian.Event.ConsumerRequest,
        )
        ) {
            val view = view()
            assertEquals(listOf(RappViewOfCustodian.Action.OpenDial), view.event(event, NOW_MS))
            assertEquals(RappViewOfCustodian.State.CONNECTING, view.state)
        }
    }

    @Test
    fun aVerifiedWithdrawalFromIdleWithdrawsTheIdentity() {
        val view = view()
        assertEquals(
            listOf(RappViewOfCustodian.Action.WithdrawIdentity),
            view.event(RappViewOfCustodian.Event.WithdrawnRecordMatched, NOW_MS),
        )
        assertEquals(RappViewOfCustodian.State.WITHDRAWN, view.state)
    }

    @Test
    fun aDialThatSucceedsConnectsAndEndsNoWindow() {
        val view = view()
        view.event(RappViewOfCustodian.Event.RecordAppeared, NOW_MS)
        assertEquals(
            listOf(RappViewOfCustodian.Action.EndRedialWindow),
            view.event(RappViewOfCustodian.Event.DialSucceeded, NOW_MS),
        )
        assertEquals(RappViewOfCustodian.State.CONNECTED, view.state)
        assertNull(view.redialWindowUntilMs)
    }

    @Test
    fun aFirstFailedDialOpensTheWindowAndSchedulesARedial() {
        val view = view()
        view.event(RappViewOfCustodian.Event.ConsumerRequest, NOW_MS)
        assertEquals(
            listOf(
                RappViewOfCustodian.Action.ScheduleRedial(RappViewOfCustodian.FIRST_REDIAL_DELAY_MS),
            ),
            view.event(RappViewOfCustodian.Event.DialFailed, NOW_MS),
        )
        assertEquals(RappViewOfCustodian.State.CONNECTING, view.state)
        assertEquals(NOW_MS + RappViewOfCustodian.REDIAL_WINDOW_MS, view.redialWindowUntilMs)
    }

    @Test
    fun redialsBackOffAndStopWhenTheWindowEnds() {
        val view = view()
        view.event(RappViewOfCustodian.Event.RecordAppeared, NOW_MS)
        val delays = mutableListOf<Long>()
        var nowMs = NOW_MS
        repeat(REDIALS_OBSERVED) {
            val scheduled =
                view.event(RappViewOfCustodian.Event.DialFailed, nowMs).single()
                    as RappViewOfCustodian.Action.ScheduleRedial
            delays += scheduled.delayMs
            nowMs += scheduled.delayMs
            assertEquals(
                listOf(RappViewOfCustodian.Action.OpenDial),
                view.event(RappViewOfCustodian.Event.RedialDue, nowMs),
            )
            assertEquals(RappViewOfCustodian.State.CONNECTING, view.state)
        }
        assertEquals(
            listOf(
                RappViewOfCustodian.FIRST_REDIAL_DELAY_MS,
                RappViewOfCustodian.FIRST_REDIAL_DELAY_MS * RappViewOfCustodian.REDIAL_BACKOFF_FACTOR,
                RappViewOfCustodian.FIRST_REDIAL_DELAY_MS *
                    RappViewOfCustodian.REDIAL_BACKOFF_FACTOR *
                    RappViewOfCustodian.REDIAL_BACKOFF_FACTOR,
                RappViewOfCustodian.FIRST_REDIAL_DELAY_MS *
                    RappViewOfCustodian.REDIAL_BACKOFF_FACTOR *
                    RappViewOfCustodian.REDIAL_BACKOFF_FACTOR *
                    RappViewOfCustodian.REDIAL_BACKOFF_FACTOR,
                RappViewOfCustodian.MAX_REDIAL_DELAY_MS,
            ),
            delays,
        )
        assertEquals(
            listOf(RappViewOfCustodian.Action.EndRedialWindow),
            view.event(RappViewOfCustodian.Event.RedialWindowEnded(dialRunning = false), WINDOW_END_MS),
        )
        assertEquals(RappViewOfCustodian.State.IDLE, view.state)
        assertNull(view.redialWindowUntilMs)
    }

    @Test
    fun aFailedDialWithTheWindowSpentIdles() {
        val view = view()
        view.event(RappViewOfCustodian.Event.RecordAppeared, NOW_MS)
        view.event(RappViewOfCustodian.Event.DialFailed, NOW_MS)
        assertEquals(
            listOf(RappViewOfCustodian.Action.EndRedialWindow),
            view.event(RappViewOfCustodian.Event.DialFailed, AFTER_WINDOW_END_MS),
        )
        assertEquals(RappViewOfCustodian.State.IDLE, view.state)
    }

    @Test
    fun aFailedDialJustInsideTheWindowRedials() {
        val view = view()
        view.event(RappViewOfCustodian.Event.RecordAppeared, NOW_MS)
        view.event(RappViewOfCustodian.Event.DialFailed, NOW_MS)
        val scheduled =
            view.event(RappViewOfCustodian.Event.DialFailed, BEFORE_WINDOW_END_MS).single()
        assertTrue(scheduled is RappViewOfCustodian.Action.ScheduleRedial)
        assertEquals(RappViewOfCustodian.State.CONNECTING, view.state)
    }

    @Test
    fun aDialRunningOutlivesTheWindowEnd() {
        val view = view()
        view.event(RappViewOfCustodian.Event.RecordAppeared, NOW_MS)
        view.event(RappViewOfCustodian.Event.DialFailed, NOW_MS)
        assertEquals(
            emptyList<RappViewOfCustodian.Action>(),
            view.event(RappViewOfCustodian.Event.RedialWindowEnded(dialRunning = true), WINDOW_END_MS),
        )
        assertEquals(RappViewOfCustodian.State.CONNECTING, view.state)
    }

    @Test
    fun anAppearanceWhileConnectingRedialsAtOnce() {
        val view = view()
        view.event(RappViewOfCustodian.Event.RecordAppeared, NOW_MS)
        assertEquals(
            listOf(RappViewOfCustodian.Action.AbortDial, RappViewOfCustodian.Action.OpenDial),
            view.event(RappViewOfCustodian.Event.RecordAppeared, NOW_MS),
        )
        assertEquals(RappViewOfCustodian.State.CONNECTING, view.state)
    }

    @Test
    fun aLossOpensTheWindowAtOnceAndKeepsTheOfferThroughItsGrace() {
        val view = connected()
        assertEquals(
            listOf(
                RappViewOfCustodian.Action.StartOfferGrace,
                RappViewOfCustodian.Action.ScheduleRedial(RappViewOfCustodian.FIRST_REDIAL_DELAY_MS),
            ),
            view.event(RappViewOfCustodian.Event.SessionLost, NOW_MS),
        )
        assertEquals(RappViewOfCustodian.State.CONNECTING, view.state)
        assertEquals(NOW_MS + RappViewOfCustodian.REDIAL_WINDOW_MS, view.redialWindowUntilMs)
    }

    @Test
    fun aViolationKeepsThePairingAndDoesNotRedial() {
        val view = connected()
        assertEquals(
            listOf(RappViewOfCustodian.Action.StartOfferGrace),
            view.event(RappViewOfCustodian.Event.ProtocolViolation, NOW_MS),
        )
        assertEquals(RappViewOfCustodian.State.IDLE, view.state)
        assertNull(view.redialWindowUntilMs)
    }

    @Test
    fun aViolationWhileConnectingEndsTheWindow() {
        val view = view()
        view.event(RappViewOfCustodian.Event.RecordAppeared, NOW_MS)
        view.event(RappViewOfCustodian.Event.DialFailed, NOW_MS)
        assertEquals(
            listOf(RappViewOfCustodian.Action.AbortDial, RappViewOfCustodian.Action.EndRedialWindow),
            view.event(RappViewOfCustodian.Event.ProtocolViolation, NOW_MS),
        )
        assertEquals(RappViewOfCustodian.State.IDLE, view.state)
        assertNull(view.redialWindowUntilMs)
    }

    @Test
    fun aWithdrawalWhileConnectingDropsTheIdentityAndWaits() {
        val view = view()
        view.event(RappViewOfCustodian.Event.RecordAppeared, NOW_MS)
        view.event(RappViewOfCustodian.Event.DialFailed, NOW_MS)
        assertEquals(
            listOf(
                RappViewOfCustodian.Action.AbortDial,
                RappViewOfCustodian.Action.EndRedialWindow,
                RappViewOfCustodian.Action.WithdrawIdentity,
            ),
            view.event(RappViewOfCustodian.Event.Withdrawn, NOW_MS),
        )
        assertEquals(RappViewOfCustodian.State.WITHDRAWN, view.state)
        assertNull(view.redialWindowUntilMs)
        assertEquals(
            listOf(RappViewOfCustodian.Action.OpenDial),
            view.event(RappViewOfCustodian.Event.RecordAppeared, NOW_MS),
        )
        assertEquals(RappViewOfCustodian.State.CONNECTING, view.state)
    }

    @Test
    fun aWithdrawalDropsTheIdentityAndWaitsForTheNextAnnouncement() {
        val view = connected()
        assertEquals(
            listOf(RappViewOfCustodian.Action.WithdrawIdentity),
            view.event(RappViewOfCustodian.Event.Withdrawn, NOW_MS),
        )
        assertEquals(RappViewOfCustodian.State.WITHDRAWN, view.state)
        assertEquals(
            listOf(RappViewOfCustodian.Action.OpenDial),
            view.event(RappViewOfCustodian.Event.RecordAppeared, NOW_MS),
        )
        assertEquals(RappViewOfCustodian.State.CONNECTING, view.state)
    }

    @Test
    fun aConsumerWhileWithdrawnIsRefusedAtOnce() {
        val view = connected()
        view.event(RappViewOfCustodian.Event.Withdrawn, NOW_MS)
        assertEquals(
            listOf(RappViewOfCustodian.Action.RefuseConsumer),
            view.event(RappViewOfCustodian.Event.ConsumerRequest, NOW_MS),
        )
        assertEquals(RappViewOfCustodian.State.WITHDRAWN, view.state)
    }

    @Test
    fun aRevocationEndsThePairingWithTheNotice() {
        val view = connected()
        assertEquals(
            listOf(RappViewOfCustodian.Action.WithdrawIdentity, RappViewOfCustodian.Action.ShowPeerForgot),
            view.event(RappViewOfCustodian.Event.PairingRevoked, NOW_MS),
        )
        assertEquals(RappViewOfCustodian.State.ENDED, view.state)
    }

    @Test
    fun aRevokingCloseBeforeReadyEndsTheDialWithTheNotice() {
        val view = view()
        view.event(RappViewOfCustodian.Event.RecordAppeared, NOW_MS)
        assertEquals(
            listOf(RappViewOfCustodian.Action.WithdrawIdentity, RappViewOfCustodian.Action.ShowPeerForgot),
            view.event(RappViewOfCustodian.Event.PairingRevoked, NOW_MS),
        )
        assertEquals(RappViewOfCustodian.State.ENDED, view.state)
    }

    @Test
    fun discoveryStoppingEndsEveryState() {
        val idle = view()
        assertEquals(
            listOf(RappViewOfCustodian.Action.WithdrawIdentity),
            idle.event(RappViewOfCustodian.Event.PairingLeft, NOW_MS),
        )
        assertEquals(RappViewOfCustodian.State.ENDED, idle.state)

        val connecting = view()
        connecting.event(RappViewOfCustodian.Event.RecordAppeared, NOW_MS)
        assertEquals(
            listOf(
                RappViewOfCustodian.Action.AbortDial,
                RappViewOfCustodian.Action.EndRedialWindow,
                RappViewOfCustodian.Action.WithdrawIdentity,
            ),
            connecting.event(RappViewOfCustodian.Event.PairingLeft, NOW_MS),
        )
        assertEquals(RappViewOfCustodian.State.ENDED, connecting.state)

        val connected = connected()
        assertEquals(
            listOf(RappViewOfCustodian.Action.WithdrawIdentity, RappViewOfCustodian.Action.RequestLocalClose),
            connected.event(RappViewOfCustodian.Event.PairingLeft, NOW_MS),
        )
        assertEquals(RappViewOfCustodian.State.ENDED, connected.state)

        val withdrawn = connected()
        withdrawn.event(RappViewOfCustodian.Event.Withdrawn, NOW_MS)
        assertEquals(
            listOf(RappViewOfCustodian.Action.WithdrawIdentity),
            withdrawn.event(RappViewOfCustodian.Event.PairingLeft, NOW_MS),
        )
        assertEquals(RappViewOfCustodian.State.ENDED, withdrawn.state)
    }

    @Test
    fun anOpenSessionOutranksDiscovery() {
        val view = connected()
        assertEquals(
            emptyList<RappViewOfCustodian.Action>(),
            view.event(RappViewOfCustodian.Event.RecordAppeared, NOW_MS),
        )
        assertEquals(
            emptyList<RappViewOfCustodian.Action>(),
            view.event(RappViewOfCustodian.Event.WithdrawnRecordMatched, NOW_MS),
        )
        assertEquals(emptyList<RappViewOfCustodian.Action>(), view.event(RappViewOfCustodian.Event.SightLost, NOW_MS))
        assertEquals(RappViewOfCustodian.State.CONNECTED, view.state)
    }

    @Test
    fun aLostSightChangesNothingWhileIdleOrConnecting() {
        val idle = view()
        assertEquals(emptyList<RappViewOfCustodian.Action>(), idle.event(RappViewOfCustodian.Event.SightLost, NOW_MS))
        assertEquals(RappViewOfCustodian.State.IDLE, idle.state)

        val connecting = view()
        connecting.event(RappViewOfCustodian.Event.RecordAppeared, NOW_MS)
        assertEquals(
            emptyList<RappViewOfCustodian.Action>(),
            connecting.event(RappViewOfCustodian.Event.SightLost, NOW_MS),
        )
        assertEquals(RappViewOfCustodian.State.CONNECTING, connecting.state)
    }

    @Test
    fun anEndedViewTakesNothing() {
        val view = connected()
        view.event(RappViewOfCustodian.Event.PairingRevoked, NOW_MS)
        for (
        event in
        listOf(
            RappViewOfCustodian.Event.RecordAppeared,
            RappViewOfCustodian.Event.ConsumerRequest,
            RappViewOfCustodian.Event.RedialDue,
            RappViewOfCustodian.Event.DialSucceeded,
            RappViewOfCustodian.Event.DialFailed,
            RappViewOfCustodian.Event.PairingLeft,
        )
        ) {
            assertEquals(emptyList<RappViewOfCustodian.Action>(), view.event(event, NOW_MS))
        }
        assertEquals(RappViewOfCustodian.State.ENDED, view.state)
    }
}
