package fi.refineid.android.nfc

import android.content.Context
import android.media.AudioManager
import android.media.ToneGenerator
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager

internal class NfcFeedback(
    context: Context,
) {
    private val vibrator: Vibrator? =
        (context.getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as? VibratorManager)?.defaultVibrator

    private val toneGenerator: ToneGenerator? =
        try {
            ToneGenerator(AudioManager.STREAM_MUSIC, FEEDBACK_TONE_VOLUME)
        } catch (_: Exception) {
            null
        }

    private var lastDiscoveryAtMillis = 0L

    /** One cue per arrival: the stack's re-polls of a resting card stay quiet. */
    fun onCardDiscovered() {
        val now = System.currentTimeMillis()
        if (now - lastDiscoveryAtMillis < DISCOVERY_QUIET_MS) return
        lastDiscoveryAtMillis = now
        playTone(ToneGenerator.TONE_PROP_BEEP, DISCOVERY_BEEP_DURATION_MS)
        vibrate(DISCOVERY_VIBRATION_MS)
    }

    fun onCardSuccess() {
        playTone(ToneGenerator.TONE_PROP_ACK, SUCCESS_BEEP_DURATION_MS)
        vibrate(SUCCESS_VIBRATION_MS)
    }

    fun onCardError() {
        playTone(ToneGenerator.TONE_PROP_NACK, ERROR_BEEP_DURATION_MS)
    }

    private fun playTone(
        toneType: Int,
        durationMs: Int,
    ) {
        try {
            toneGenerator?.startTone(toneType, durationMs)
        } catch (_: Exception) {
        }
    }

    private fun vibrate(durationMs: Long) {
        try {
            if (vibrator?.hasVibrator() == true) {
                vibrator.vibrate(
                    VibrationEffect.createOneShot(durationMs, VibrationEffect.DEFAULT_AMPLITUDE),
                )
            }
        } catch (_: Exception) {
        }
    }

    private companion object {
        const val FEEDBACK_TONE_VOLUME = 70
        const val DISCOVERY_BEEP_DURATION_MS = 40
        const val DISCOVERY_QUIET_MS = 1_500L
        const val DISCOVERY_VIBRATION_MS = 35L
        const val SUCCESS_BEEP_DURATION_MS = 80
        const val SUCCESS_VIBRATION_MS = 50L
        const val ERROR_BEEP_DURATION_MS = 120
    }
}
