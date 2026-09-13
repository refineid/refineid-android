@file:Suppress("TooGenericExceptionCaught", "SwallowedException", "MagicNumber", "MaxLineLength")

package fi.refineid.android.rapp

import android.content.Context
import android.util.Base64
import fi.refineid.android.core.AuthenticationCardService
import fi.refineid.android.core.CertificateHolderName
import fi.refineid.android.core.PersonCardDetails
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import uniffi.refineid_rapp.RappEndpointRole
import uniffi.refineid_rapp.RappPairRecord

/**
 * Manages the client-side lifecycle and state for a remote ID card
 * accessed through a paired proxy phone.
 */
internal class RemoteCardModel(
    private val context: Context,
    private val scope: CoroutineScope,
    private val vault: AndroidRappVault,
    private val catalog: RappPairCatalog,
) {
    private val _holderName = MutableStateFlow<String?>(null)
    val holderName: StateFlow<String?> = _holderName.asStateFlow()

    private val _cardDetails = MutableStateFlow<PersonCardDetails?>(null)
    val cardDetails: StateFlow<PersonCardDetails?> = _cardDetails.asStateFlow()

    private val _certificateDer = MutableStateFlow<ByteArray?>(null)
    val certificateDer: StateFlow<ByteArray?> = _certificateDer.asStateFlow()
    val cachedCertificateDer: ByteArray?
        get() = _certificateDer.value

    val authenticationCardService: AuthenticationCardService by lazy {
        RemoteAuthenticationCardService(scope, this)
    }

    private val _isConnecting = MutableStateFlow(false)
    val isConnecting: StateFlow<Boolean> = _isConnecting.asStateFlow()

    private val _hasPair = MutableStateFlow(false)
    val hasPair: StateFlow<Boolean> = _hasPair.asStateFlow()

    init {
        refreshCachedIdentity()
    }

    fun setCertificateDer(der: ByteArray) {
        _certificateDer.value = der
        val pairs = catalog.listPairs()
        if (pairs.isNotEmpty()) {
            val newest = pairs.maxByOrNull { it.createdAtMs } ?: pairs.first()
            catalog.updateCertificateDer(newest.pairIdHex, der)
        }
    }

    fun createRequesterClient(): RappRequesterClient? {
        val pairs = catalog.listPairs()
        if (pairs.isEmpty()) return null
        val newest = pairs.maxByOrNull { it.createdAtMs } ?: pairs.first()
        val pairIdBytes =
            try {
                newest.pairIdHex
                    .chunked(2)
                    .map { it.toInt(16).toByte() }
                    .toByteArray()
            } catch (_: Exception) {
                return null
            }

        val record =
            try {
                RappPairRecord.loadFromVault(pairIdBytes, vault)
            } catch (_: Exception) {
                return null
            }

        if (record.metadata().role != RappEndpointRole.REQUESTER) {
            return null
        }
        return RappRequesterClient(context, scope, record, vault)
    }

    fun refresh() {
        refreshCachedIdentity()
        val pairs = catalog.listPairs()
        if (pairs.isEmpty()) return
        val newest = pairs.maxByOrNull { it.createdAtMs } ?: pairs.first()
        val pairIdBytes =
            try {
                newest.pairIdHex
                    .chunked(2)
                    .map { it.toInt(16).toByte() }
                    .toByteArray()
            } catch (_: Exception) {
                return
            }

        val record =
            try {
                RappPairRecord.loadFromVault(pairIdBytes, vault)
            } catch (_: Exception) {
                return
            }

        if (record.metadata().role != RappEndpointRole.REQUESTER) {
            _hasPair.value = false
            return
        }

        _hasPair.value = true
        connect(record, newest.pairIdHex)
    }

    private fun refreshCachedIdentity() {
        val pairs = catalog.listPairs()
        if (pairs.isEmpty()) {
            _hasPair.value = false
            _holderName.value = null
            _cardDetails.value = null
            return
        }
        val newest = pairs.maxByOrNull { it.createdAtMs } ?: pairs.first()
        val pairIdBytes =
            try {
                newest.pairIdHex
                    .chunked(2)
                    .map { it.toInt(16).toByte() }
                    .toByteArray()
            } catch (_: Exception) {
                return
            }

        val record =
            try {
                RappPairRecord.loadFromVault(pairIdBytes, vault)
            } catch (_: Exception) {
                return
            }

        if (record.metadata().role != RappEndpointRole.REQUESTER) {
            _hasPair.value = false
            _holderName.value = null
            _cardDetails.value = null
            _certificateDer.value = null
            return
        }

        _hasPair.value = true
        if (!newest.certificateDerBase64.isNullOrBlank()) {
            try {
                _certificateDer.value = Base64.decode(newest.certificateDerBase64, Base64.NO_WRAP)
            } catch (_: Exception) {
            }
        }
        if (!newest.holderName.isNullOrBlank()) {
            _holderName.value = newest.holderName
            _cardDetails.value = PersonCardDetails.fromHolderName(newest.holderName)
        } else {
            _holderName.value = null
            _cardDetails.value = null
        }
    }

    fun connect(
        record: RappPairRecord? = null,
        pairIdHex: String? = null,
    ) {
        if (_isConnecting.value) return
        scope.launch(Dispatchers.IO) {
            _isConnecting.value = true
            try {
                val currentRecord =
                    record ?: run {
                        val pairs = catalog.listPairs()
                        if (pairs.isEmpty()) return@launch
                        val newest = pairs.maxByOrNull { it.createdAtMs } ?: pairs.first()
                        val bytes =
                            newest.pairIdHex
                                .chunked(2)
                                .map { it.toInt(16).toByte() }
                                .toByteArray()
                        RappPairRecord.loadFromVault(bytes, vault)
                    }
                val currentPairIdHex =
                    pairIdHex ?: currentRecord.metadata().pairId.joinToString("") { "%02x".format(it) }

                val client = RappRequesterClient(context, scope, currentRecord, vault)
                val certDer = client.readAuthenticationCertificate(timeoutMs = 15_000L)
                if (certDer != null) {
                    setCertificateDer(certDer)
                    val name = CertificateHolderName.fromDer(certDer)
                    val details = PersonCardDetails.fromDer(certDer)
                    if (name != null) {
                        _holderName.value = name
                        _cardDetails.value = details ?: PersonCardDetails.fromHolderName(name)
                        catalog.updateHolderName(currentPairIdHex, name)
                    }
                }
            } catch (e: Exception) {
                android.util.Log.e("REMOTE_CARD_MODEL", "connect failed", e)
            } finally {
                _isConnecting.value = false
            }
        }
    }

    fun forget() {
        _certificateDer.value = null
        _holderName.value = null
        _cardDetails.value = null
        _hasPair.value = false
        val pairs = catalog.listPairs()
        for (p in pairs) {
            try {
                val bytes =
                    p.pairIdHex
                        .chunked(2)
                        .map { it.toInt(16).toByte() }
                        .toByteArray()
                vault.revokeDeviceOnly(bytes, RappClock.wallMs())
            } catch (_: Exception) {
            }
            catalog.removePair(p.pairIdHex)
        }
        catalog.clearAll()
    }
}
