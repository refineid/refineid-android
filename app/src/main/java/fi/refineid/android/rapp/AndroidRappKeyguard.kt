// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import android.app.KeyguardManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.ContextCompat
import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume

/**
 * The platform keyguard: [KeyguardManager.isKeyguardLocked] says whether it
 * is showing, and the `ACTION_USER_PRESENT` broadcast, which only the system
 * sends, says when the holder dismissed it. A phone without a keyguard
 * never reads locked.
 */
internal class AndroidRappKeyguard(
    private val context: Context,
) : RappKeyguard {
    private val keyguardManager: KeyguardManager?
        get() = context.getSystemService(KeyguardManager::class.java)

    override val isLocked: Boolean
        get() = keyguardManager?.isKeyguardLocked == true

    override suspend fun awaitUnlocked() {
        if (!isLocked) return
        suspendCancellableCoroutine { continuation ->
            val done = AtomicBoolean(false)
            lateinit var receiver: BroadcastReceiver
            val finish = {
                if (done.compareAndSet(false, true)) {
                    try {
                        context.unregisterReceiver(receiver)
                    } catch (_: IllegalArgumentException) {
                        // Never registered.
                    }
                    if (continuation.isActive) continuation.resume(Unit)
                }
            }
            receiver =
                object : BroadcastReceiver() {
                    override fun onReceive(
                        context: Context,
                        intent: Intent,
                    ) {
                        if (intent.action == Intent.ACTION_USER_PRESENT) finish()
                    }
                }
            ContextCompat.registerReceiver(
                context,
                receiver,
                IntentFilter(Intent.ACTION_USER_PRESENT),
                ContextCompat.RECEIVER_NOT_EXPORTED,
            )
            continuation.invokeOnCancellation { finish() }
            // An unlock between the check and the registration sent no broadcast this receiver saw.
            if (!isLocked) finish()
        }
    }
}
