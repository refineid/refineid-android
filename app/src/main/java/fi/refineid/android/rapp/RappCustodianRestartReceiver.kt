package fi.refineid.android.rapp

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import fi.refineid.android.RefineIdApplication

/**
 * Brings the custodian process up after a reboot or an app update, when no
 * activity has started it. Application start-up opens the listener; this
 * receiver starts the foreground service inside the window the broadcast
 * allows.
 */
internal class RappCustodianRestartReceiver : BroadcastReceiver() {
    override fun onReceive(
        context: Context,
        intent: Intent,
    ) {
        if (intent.action !in RESTART_ACTIONS) return
        val app = context.applicationContext as? RefineIdApplication ?: return
        if (app.rappProxyDispatcher.isListening) {
            RappCustodianService.ensureRunning(app)
        }
    }

    private companion object {
        val RESTART_ACTIONS = setOf(Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_MY_PACKAGE_REPLACED)
    }
}
