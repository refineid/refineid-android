package fi.refineid.android.rapp

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import org.json.JSONArray
import org.json.JSONObject
import java.util.Base64

internal data class PairedPeer(
    val pairIdHex: String,
    val displayName: String,
    val platform: String,
    val createdAtMs: Long,
    val holderName: String? = null,
    val certificateDerBase64: String? = null,
    val lastUsedMs: Long = createdAtMs,
    /**
     * When the local user forgot the pairing while no session to its peer
     * was open; the record then only waits to deliver the `pairing_revoked`
     * close (RAPP v26.10.22 section 4.6 item 2).
     */
    val forgottenAtMs: Long? = null,
)

/** Persists authenticated RAPP paired devices locally on Android. */
internal class RappPairCatalog(
    private val prefs: SharedPreferences,
) {
    constructor(context: Context) : this(
        context.getSharedPreferences("fi.refineid.rapp.pairs", Context.MODE_PRIVATE),
    )

    companion object {
        private const val KEY_PAIRS = "paired_devices"
    }

    /** The pairings the user has not forgotten. */
    fun listPairs(): List<PairedPeer> = allPairs().filter { it.forgottenAtMs == null }

    /** The pairings the user forgot whose records still wait to deliver the close. */
    fun forgottenPairs(): List<PairedPeer> = allPairs().filter { it.forgottenAtMs != null }

    /** Every catalogued pairing, forgotten or not. */
    fun allPairs(): List<PairedPeer> {
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
                        holderName = obj.optString("holderName").takeIf { it.isNotBlank() },
                        certificateDerBase64 = obj.optString("certificateDerBase64").takeIf { it.isNotBlank() },
                        lastUsedMs = obj.optLong("lastUsedMs", obj.getLong("createdAtMs")),
                        forgottenAtMs = if (obj.has("forgottenAtMs")) obj.getLong("forgottenAtMs") else null,
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
        val updated = allPairs().filter { it.pairIdHex != hex }.toMutableList()
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
    ) = update(pairIdHex) { it.copy(holderName = holderName) }

    fun updateCertificateDer(
        pairIdHex: String,
        certDer: ByteArray,
    ) {
        val b64 = Base64.getEncoder().encodeToString(certDer)
        update(pairIdHex) { it.copy(certificateDerBase64 = b64) }
    }

    /** Records that the pairing [pairIdHex] carried a session at [nowMs]. */
    fun markUsed(
        pairIdHex: String,
        nowMs: Long,
    ) = update(pairIdHex) { it.copy(lastUsedMs = nowMs) }

    /** Records that the user forgot [pairIdHex] at [atMs] while its record waits to deliver the close. */
    fun markForgotten(
        pairIdHex: String,
        atMs: Long,
    ) = update(pairIdHex) { it.copy(forgottenAtMs = atMs) }

    fun removePair(pairIdHex: String) {
        persistPairs(allPairs().filter { it.pairIdHex != pairIdHex })
    }

    private fun update(
        pairIdHex: String,
        change: (PairedPeer) -> PairedPeer,
    ) {
        persistPairs(allPairs().map { peer -> if (peer.pairIdHex == pairIdHex) change(peer) else peer })
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
            obj.put("lastUsedMs", p.lastUsedMs)
            p.forgottenAtMs?.let { obj.put("forgottenAtMs", it) }
            arr.put(obj)
        }
        prefs.edit { putString(KEY_PAIRS, arr.toString()) }
    }
}
