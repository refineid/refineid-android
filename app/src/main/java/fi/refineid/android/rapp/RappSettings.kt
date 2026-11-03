package fi.refineid.android.rapp

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit

/**
 * The phone's Remote Access switch and the computer's remote-use switch.
 * Each moves only by the holder's own action and keeps its position across
 * launches; each starts off (RAPP v26.11.2 section 4.7, discovery hierarchy
 * section 5.2).
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

    var isRequesterRemoteUseEnabled: Boolean
        get() = prefs.getBoolean(KEY_REQUESTER_REMOTE_USE_ENABLED, false)
        set(value) {
            prefs.edit { putBoolean(KEY_REQUESTER_REMOTE_USE_ENABLED, value) }
        }

    companion object {
        const val PREFS_NAME = "fi.refineid.rapp.settings"
        const val KEY_CARD_REMOTE_ACCESS_ENABLED = "card_remote_access_enabled"
        const val KEY_REQUESTER_REMOTE_USE_ENABLED = "requester_remote_use_enabled"
    }
}
