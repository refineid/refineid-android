package fi.refineid.android.rapp

import android.content.Context
import android.util.Base64
import androidx.core.content.edit
import org.json.JSONArray
import org.json.JSONObject

internal data class PairedPeer(
    val pairIdHex: String,
    val displayName: String,
    val platform: String,
    val createdAtMs: Long,
    val holderName: String? = null,
    val certificateDerBase64: String? = null,
)

/** Persists authenticated RAPP paired devices locally on Android. */
internal class RappPairCatalog(
    context: Context,
) {
    private val prefs = context.getSharedPreferences("fi.refineid.rapp.pairs", Context.MODE_PRIVATE)

    companion object {
        private const val KEY_PAIRS = "paired_devices"
        private const val KEY_SELECTED = "selected_pair_id"
    }

    fun listPairs(): List<PairedPeer> {
        val raw = prefs.getString(KEY_PAIRS, null) ?: return emptyList()
        val result = mutableListOf<PairedPeer>()
        try {
            val arr = JSONArray(raw)
            for (i in 0 until arr.length()) {
                val obj = arr.getJSONObject(i)
                result.add(
                    PairedPeer(
                        pairIdHex = obj.getString("pairIdHex"),
                        displayName = obj.getString("displayName"),
                        platform = obj.getString("platform"),
                        createdAtMs = obj.getLong("createdAtMs"),
                        holderName =
                            if (obj.has("holderName") && !obj.isNull("holderName")) {
                                obj.getString("holderName")
                            } else {
                                null
                            },
                        certificateDerBase64 =
                            if (obj.has("certificateDerBase64") && !obj.isNull("certificateDerBase64")) {
                                obj.getString("certificateDerBase64")
                            } else {
                                null
                            },
                    ),
                )
            }
        } catch (_: Exception) {
        }
        return result
    }

    fun savePair(
        pairId: ByteArray,
        displayName: String,
        platform: String,
        createdAtMs: Long,
        holderName: String? = null,
        certificateDerBase64: String? = null,
    ) {
        val hex = pairId.joinToString("") { "%02x".format(it) }
        val updated = listPairs().filter { it.pairIdHex != hex }.toMutableList()
        updated.add(
            PairedPeer(
                pairIdHex = hex,
                displayName = displayName,
                platform = platform,
                createdAtMs = createdAtMs,
                holderName = holderName,
                certificateDerBase64 = certificateDerBase64,
            ),
        )
        persistPairs(updated)
    }

    fun updateHolderName(
        pairIdHex: String,
        holderName: String,
    ) {
        val current =
            listPairs().map { peer ->
                if (peer.pairIdHex == pairIdHex) {
                    peer.copy(holderName = holderName)
                } else {
                    peer
                }
            }
        persistPairs(current)
    }

    fun updateCertificateDer(
        pairIdHex: String,
        certDer: ByteArray,
    ) {
        val b64 = Base64.encodeToString(certDer, Base64.NO_WRAP)
        val current =
            listPairs().map { peer ->
                if (peer.pairIdHex == pairIdHex) {
                    peer.copy(certificateDerBase64 = b64)
                } else {
                    peer
                }
            }
        persistPairs(current)
    }

    fun removePair(pairIdHex: String) {
        val current = listPairs().filter { it.pairIdHex != pairIdHex }
        persistPairs(current)
    }

    fun clearAll() {
        prefs.edit { remove(KEY_PAIRS) }
    }

    private fun persistPairs(pairs: List<PairedPeer>) {
        val arr = JSONArray()
        for (p in pairs) {
            val obj = JSONObject()
            obj.put("pairIdHex", p.pairIdHex)
            obj.put("displayName", p.displayName)
            obj.put("platform", p.platform)
            obj.put("createdAtMs", p.createdAtMs)
            p.holderName?.let { obj.put("holderName", it) }
            p.certificateDerBase64?.let { obj.put("certificateDerBase64", it) }
            arr.put(obj)
        }
        prefs.edit { putString(KEY_PAIRS, arr.toString()) }
    }
}
