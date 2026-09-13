package fi.refineid.android.rapp

import android.annotation.SuppressLint
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import fi.refineid.android.MainActivity
import fi.refineid.android.R

/** Posts heads-up notifications when an incoming signature request arrives from a paired Mac/iPad. */
@SuppressLint("MissingPermission")
internal class RappNotificationManager(
    private val context: Context,
) {
    companion object {
        const val CHANNEL_ID = "refineid_signing_requests"
        const val NOTIFICATION_ID = 26822
        const val ACTION_AUTHORIZE = "fi.refineid.android.ACTION_RAPP_AUTHORIZE"
        const val EXTRA_REQUEST_ID = "rapp_request_id"
    }

    init {
        createNotificationChannel()
    }

    private fun createNotificationChannel() {
        val name = context.getString(R.string.app_name)
        val descriptionText = "Notifications for cross-device authentication and signing requests"
        val importance = NotificationManager.IMPORTANCE_HIGH
        val channel =
            NotificationChannel(CHANNEL_ID, name, importance).apply {
                description = descriptionText
                enableVibration(true)
                setShowBadge(true)
            }
        val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
        notificationManager?.createNotificationChannel(channel)
    }

    fun postAuthorizationNotification(requestId: String) {
        val intent =
            Intent(context, MainActivity::class.java).apply {
                setClass(context, MainActivity::class.java)
                setPackage(context.packageName)
                action = ACTION_AUTHORIZE
                putExtra(EXTRA_REQUEST_ID, requestId)
                flags =
                    Intent.FLAG_ACTIVITY_NEW_TASK or
                    Intent.FLAG_ACTIVITY_SINGLE_TOP or
                    Intent.FLAG_ACTIVITY_CLEAR_TOP
            }

        val pendingIntent =
            PendingIntent.getActivity(
                context,
                requestId.hashCode(),
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )

        val title = context.getString(R.string.phone_needs_id_card)
        val body = context.getString(R.string.hold_card_against_back)
        val notification =
            NotificationCompat
                .Builder(context, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
                .setContentTitle(title)
                .setContentText(body)
                .setStyle(
                    NotificationCompat.BigTextStyle().bigText(body),
                ).setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_CALL)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .build()

        try {
            NotificationManagerCompat.from(context).notify(NOTIFICATION_ID, notification)
        } catch (_: SecurityException) {
        }
    }

    fun dismissNotification() {
        try {
            NotificationManagerCompat.from(context).cancel(NOTIFICATION_ID)
        } catch (_: SecurityException) {
        }
    }
}
