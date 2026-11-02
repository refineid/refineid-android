package fi.refineid.android.rapp

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit

/**
 * The phone's Remote Access switch. It moves only by the holder's own
 * action and keeps its position across launches; it starts off (RAPP
 * v26.11.2 section 4.7).
 */
internal class RappSettings(
    private val prefs: SharedPreferences,
) {
    constructor(context: Context) : this(
        prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE),
    )

    var isCardRemoteAccessEnabled: Boolean
        get() = prefs.getBoolean(KEY_CARD_REMOTE_ACCESS_ENABLED, false)
        set(value) {
            prefs.edit { putBoolean(KEY_CARD_REMOTE_ACCESS_ENABLED, value) }
        }

    companion object {
        const val PREFS_NAME = "fi.refineid.rapp.settings"
        const val KEY_CARD_REMOTE_ACCESS_ENABLED = "card_remote_access_enabled"
    }
}
