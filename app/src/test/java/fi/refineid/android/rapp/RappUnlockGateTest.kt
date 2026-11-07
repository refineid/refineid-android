// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The held PIN 1 answers a browser authentication with no prompt, but a
 * locked phone does not serve it: the request waits for the holder to
 * unlock, and the operation's deadline ends a wait still locked without a
 * signature (ADR 0040).
 */
class RappUnlockGateTest {
    private companion object {
        /** How long a test lets the gate come back once the holder unlocked. */
        const val SETTLE_MS = 5_000L

        /** Turns of the scheduler a waiting gate gets to prove it stays waiting. */
        const val IDLE_TURNS = 10
    }

    /** A keyguard the test locks and unlocks. */
    private class ScriptedKeyguard(
        locked: Boolean,
    ) : RappKeyguard {
        private var dismissed = CompletableDeferred<Unit>().also { if (!locked) it.complete(Unit) }

        override val isLocked: Boolean
            get() = !dismissed.isCompleted

        override suspend fun awaitUnlocked() = dismissed.await()

        fun unlock() {
            dismissed.complete(Unit)
        }
    }

    /** The holder's view of one wait: the request notification posted and withdrawn. */
    private class Holder {
        var told = 0
        var withdrawn = 0
    }

    /** The authentication as the dispatcher runs it: through the gate, then the signature with the held PIN 1. */
    private class Authentication(
        val keyguard: ScriptedKeyguard,
    ) {
        val holder = Holder()
        var signed = false
        var waited = false

        suspend fun run() {
            waited =
                RappUnlockGate.awaitUnlocked(
                    keyguard,
                    tell = { holder.told++ },
                    withdraw = { holder.withdrawn++ },
                )
            signed = true
        }
    }

    private suspend fun Deferred<Unit>.stillWaiting(): Boolean {
        repeat(IDLE_TURNS) { yield() }
        return isActive
    }

    @Test
    fun anUnlockedPhoneServesTheHeldPinAtOnce() =
        runBlocking {
            val authentication = Authentication(ScriptedKeyguard(locked = false))

            authentication.run()

            assertTrue("the held PIN 1 signs with no wait", authentication.signed)
            assertFalse(authentication.waited)
            assertEquals("nothing is told to a holder who is already there", 0, authentication.holder.told)
            assertEquals(0, authentication.holder.withdrawn)
        }

    @Test
    fun aLockedPhoneWaitsForTheHolderToUnlockAndThenSigns() =
        runBlocking {
            val keyguard = ScriptedKeyguard(locked = true)
            val authentication = Authentication(keyguard)

            val operation = async { authentication.run() }

            assertTrue("the request waits while the keyguard shows", operation.stillWaiting())
            assertFalse("nothing is signed on a locked phone", authentication.signed)
            assertEquals("the holder is told once a request waits on the unlock", 1, authentication.holder.told)
            assertEquals(0, authentication.holder.withdrawn)

            keyguard.unlock()
            withTimeout(SETTLE_MS) { operation.await() }

            assertTrue("the held PIN 1 signs once the holder unlocked", authentication.signed)
            assertTrue(authentication.waited)
            assertEquals("the telling is withdrawn when the wait ends", 1, authentication.holder.withdrawn)
        }

    @Test
    fun theDeadlineEndsAWaitStillLockedWithoutASignature() =
        runBlocking {
            val keyguard = ScriptedKeyguard(locked = true)
            val authentication = Authentication(keyguard)

            val operation = async { authentication.run() }
            assertTrue(operation.stillWaiting())

            // The engine answers the requester when the deadline passes and the
            // dispatcher cancels the operation, as for a consent still pending.
            operation.cancelAndJoin()

            assertTrue(operation.isCancelled)
            assertFalse("a wait the deadline ended never signs", authentication.signed)
            assertEquals("the telling is withdrawn when the deadline ends the wait", 1, authentication.holder.withdrawn)
            assertTrue("the phone is still locked", keyguard.isLocked)
        }
}
