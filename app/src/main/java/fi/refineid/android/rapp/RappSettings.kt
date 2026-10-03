package fi.refineid.android.rapp

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit

internal class RappSettings(
    private val prefs: SharedPreferences,
    private val pairCatalogSupplier: () -> List<PairedPeer>,
) {
    constructor(context: Context) : this(
        prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE),
        pairCatalogSupplier = { RappPairCatalog(context.applicationContext).listPairs() },
    )

    var isCardRemoteAccessEnabled: Boolean
        get() {
            if (prefs.contains(KEY_CARD_REMOTE_ACCESS_ENABLED)) {
                return prefs.getBoolean(KEY_CARD_REMOTE_ACCESS_ENABLED, false)
            }
            // If the user already has paired devices, default to true for backward compatibility.
            // Otherwise, default to false so remote access is off until explicitly enabled.
            return pairCatalogSupplier().isNotEmpty()
        }
        set(value) {
            prefs.edit { putBoolean(KEY_CARD_REMOTE_ACCESS_ENABLED, value) }
        }

    companion object {
        const val PREFS_NAME = "fi.refineid.rapp.settings"
        const val KEY_CARD_REMOTE_ACCESS_ENABLED = "card_remote_access_enabled"
    }
}
