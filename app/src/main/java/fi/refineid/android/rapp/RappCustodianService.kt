package fi.refineid.android.rapp

import android.app.ForegroundServiceStartNotAllowedException
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import fi.refineid.android.MainActivity
import fi.refineid.android.R

/**
 * Keeps the custodian process running while the RAPP session listener is
 * open, so a paired computer reaches the card without RefineID in front.
 *
 * A cached background process is frozen and stops accepting connections;
 * a `connectedDevice` foreground service keeps it in the foreground-service
 * process state with network access. The service owns no protocol state; it
 * only carries the ongoing notification that the platform requires.
 */
internal class RappCustodianService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(
        intent: Intent?,
        flags: Int,
        startId: Int,
    ): Int {
        createChannel(this)
        val notification =
            NotificationCompat
                .Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
                .setContentTitle(getString(R.string.pair_computer))
                .setOngoing(true)
                .setSilent(true)
                .setCategory(NotificationCompat.CATEGORY_SERVICE)
                .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
                .setContentIntent(openAppIntent(this))
                .build()
        ServiceCompat.startForeground(
            this,
            NOTIFICATION_ID,
            notification,
            ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE,
        )
        return START_STICKY
    }

    companion object {
        private const val CHANNEL_ID = "refineid_remote_access"
        private const val NOTIFICATION_ID = 26821

        @Volatile
        private var running = false

        /**
         * Starts the service unless it already runs. A start the platform
         * refuses from the background is retried by the next foreground start.
         */
        fun ensureRunning(context: Context) {
            if (running) return
            try {
                context.startForegroundService(Intent(context, RappCustodianService::class.java))
                running = true
            } catch (_: ForegroundServiceStartNotAllowedException) {
                running = false
            }
        }

        fun stop(context: Context) {
            if (!running) return
            running = false
            context.stopService(Intent(context, RappCustodianService::class.java))
        }

        private fun createChannel(context: Context) {
            val channel =
                NotificationChannel(
                    CHANNEL_ID,
                    context.getString(R.string.pair_computer),
                    NotificationManager.IMPORTANCE_LOW,
                ).apply { setShowBadge(false) }
            context.getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)
        }

        private fun openAppIntent(context: Context): PendingIntent =
            PendingIntent.getActivity(
                context,
                NOTIFICATION_ID,
                Intent(context, MainActivity::class.java)
                    .setPackage(context.packageName)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP),
                PendingIntent.FLAG_IMMUTABLE,
            )
    }
}
