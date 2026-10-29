@file:Suppress("TooGenericExceptionCaught", "SwallowedException")

package fi.refineid.android.rapp

import android.content.Context
import android.util.Base64
import fi.refineid.android.BuildConfig
import fi.refineid.android.core.AuthenticationCardService
import fi.refineid.android.core.CertificateHolderName
import fi.refineid.android.core.PersonCardDetails
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import uniffi.refineid_rapp.RappBindingException
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

    private companion object {
        const val CERTIFICATE_READ_TIMEOUT_MS = 15_000L
    }

    init {
        refreshCachedIdentity()
    }

    fun setCertificateDer(der: ByteArray) {
        _certificateDer.value = der
        val newest = newestPeer() ?: return
        catalog.updateCertificateDer(newest.pairIdHex, der)
    }

    /** The most recently created pairing the user has not forgotten. */
    private fun newestPeer(): PairedPeer? = catalog.listPairs().maxByOrNull { it.createdAtMs }

    /** The record of [peer] when this device is its requester; null otherwise. */
    private fun requesterRecord(peer: PairedPeer): RappPairRecord? {
        val pairId = RappPairId.fromKey(peer.pairIdHex) ?: return null
        val record =
            try {
                RappPairRecord.loadFromVault(pairId.toWire(), vault)
            } catch (_: RappBindingException) {
                return null
            }
        val requester =
            try {
                record.pairing().role == RappEndpointRole.REQUESTER
            } catch (_: Exception) {
                false
            }
        if (!requester) record.close()
        return record.takeIf { requester }
    }

    fun createRequesterClient(): RappRequesterClient? {
        val newest = newestPeer() ?: return null
        val record = requesterRecord(newest) ?: return null
        return client(newest, record)
    }

    private fun client(
        peer: PairedPeer,
        record: RappPairRecord,
    ): RappRequesterClient =
        RappRequesterClient(context, scope, record, vault, onPairingRevoked = { pairingRevoked(peer.pairIdHex) })

    fun refresh() {
        refreshCachedIdentity()
        deliverRevocationNotices()
        val newest = newestPeer() ?: return
        val record = requesterRecord(newest)
        _hasPair.value = record != null
        if (record != null) connect(record, newest)
    }

    /**
     * Dials each forgotten pairing once to deliver its `pairing_revoked`
     * close (RAPP v26.10.29 section 4.6 item 2); one delivered is destroyed
     * and leaves the catalog.
     */
    private fun deliverRevocationNotices() {
        for (peer in catalog.forgottenPairs()) {
            val record = requesterRecord(peer) ?: continue
            scope.launch(Dispatchers.IO) {
                if (RappRequesterClient(context, scope, record, vault).deliverRevocationNotice()) {
                    catalog.removePair(peer.pairIdHex)
                }
            }
        }
    }

    private fun refreshCachedIdentity() {
        val newest = newestPeer()
        val record = newest?.let(::requesterRecord)
        if (newest == null || record == null) {
            _hasPair.value = false
            _holderName.value = null
            _cardDetails.value = null
            _certificateDer.value = null
            return
        }
        record.close()
        _hasPair.value = true
        if (!newest.certificateDerBase64.isNullOrBlank()) {
            try {
                _certificateDer.value = Base64.decode(newest.certificateDerBase64, Base64.NO_WRAP)
            } catch (_: IllegalArgumentException) {
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

    private fun connect(
        record: RappPairRecord,
        peer: PairedPeer,
    ) {
        if (_isConnecting.value) return
        scope.launch(Dispatchers.IO) {
            _isConnecting.value = true
            try {
                val certificate = client(peer, record).readAuthenticationCertificate(CERTIFICATE_READ_TIMEOUT_MS)
                if (certificate != null) {
                    val certDer = certificate.toWire()
                    setCertificateDer(certDer)
                    val name = CertificateHolderName.fromDer(certDer)
                    if (name != null) {
                        _holderName.value = name
                        _cardDetails.value =
                            PersonCardDetails.fromDer(certDer) ?: PersonCardDetails.fromHolderName(name)
                        catalog.updateHolderName(peer.pairIdHex, name)
                    }
                }
            } catch (e: Exception) {
                if (BuildConfig.DEBUG) {
                    android.util.Log.e("REMOTE_CARD_MODEL", "connect failed", e)
                }
            } finally {
                _isConnecting.value = false
            }
        }
    }

    /** The custodian forgot the pairing: its identity is withdrawn at once (RAPP v26.10.29 section 4.6 item 4). */
    private fun pairingRevoked(pairIdHex: String) {
        catalog.removePair(pairIdHex)
        withdrawIdentity()
    }

    private fun withdrawIdentity() {
        _certificateDer.value = null
        _holderName.value = null
        _cardDetails.value = null
        _hasPair.value = false
    }

    /**
     * Forgets every pairing (RAPP v26.10.29 section 4.6): each record keeps its
     * key only to deliver the `pairing_revoked` close on its next session.
     */
    fun forget() {
        withdrawIdentity()
        for (peer in catalog.listPairs()) {
            val pairId = RappPairId.fromKey(peer.pairIdHex)
            if (pairId != null && RappPairRevocation.forget(pairId, vault)) {
                catalog.markForgotten(peer.pairIdHex, System.currentTimeMillis())
            } else {
                catalog.removePair(peer.pairIdHex)
            }
        }
    }
}
