@file:Suppress("TooGenericExceptionCaught", "SwallowedException", "DEPRECATION")

package fi.refineid.android.rapp

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import fi.refineid.android.BuildConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import uniffi.refineid_rapp.RappPairRecord

/**
 * What one resolved stream service means to the requester holding
 * [pairRecord], or null when it means nothing.
 */
internal sealed interface RappSighting {
    /** The custodian appeared: dial it. [hintMatched] says its hint named the pairing. */
    data class Appeared(
        val hintMatched: Boolean,
    ) : RappSighting

    /** The custodian withdrew on the associated instance: stop dialing and offering. */
    data object WithdrawnMatched : RappSighting
}

/**
 * Classifies resolved stream services for one pairing (RAPP v26.11.2
 * section 4.5 item 6, section 8.3).
 *
 * A `mode=session` record whose hint names the pairing, or one carrying no
 * hints, puts the custodian in sight; routing decides the hint-less one.
 * The first sight of an instance, a fresh instance name, or one back after
 * vanishing is an appearance. A withdrawn record is honored only on the
 * associated instance: the instance whose hint matched, or the last one a
 * session was established to. Anything else, including a withdrawn record
 * without a match, is unannounced loss and means nothing here.
 *
 * The class holds no Android types; the times are whole Unix seconds for
 * the hint windows.
 */
internal class RappRequesterSightings {
    private val inSight = HashSet<String>()

    /**
     * What the service [instance] resolved with [attributes] means, or null
     * when it means nothing. [associatedInstance] is the instance the
     * pairing's discovery is associated with, if any.
     */
    fun resolved(
        instance: String,
        attributes: Map<String, ByteArray?>,
        associatedInstance: String?,
        pairRecord: RappPairRecord,
        nowUnixSeconds: Long,
    ): RappSighting? {
        if (instance == associatedInstance && matchesWithdrawn(instance, attributes, pairRecord, nowUnixSeconds)) {
            return RappSighting.WithdrawnMatched
        }
        if (!StreamRendezvousName.matches(attributes, StreamRendezvousName.MODE_SESSION)) return null
        val hintMatched = hintMatches(pairRecord, attributes, nowUnixSeconds)
        if (!hintMatched && StreamRendezvousName.hasHints(attributes)) return null
        return if (inSight.add(instance)) RappSighting.Appeared(hintMatched) else null
    }

    /** The service [instance] vanished; its next sight is an appearance again. */
    fun lost(instance: String) {
        inSight.remove(instance)
    }

    private fun matchesWithdrawn(
        instance: String,
        attributes: Map<String, ByteArray?>,
        pairRecord: RappPairRecord,
        nowUnixSeconds: Long,
    ): Boolean =
        try {
            pairRecord.matchesWithdrawnRecord(
                instance,
                StreamRendezvousName.entries(attributes),
                nowUnixSeconds.toULong(),
            )
        } catch (_: Exception) {
            false
        }

    private fun hintMatches(
        pairRecord: RappPairRecord,
        attributes: Map<String, ByteArray?>,
        nowUnixSeconds: Long,
    ): Boolean =
        try {
            pairRecord.matchesDiscoveryRecord(
                StreamRendezvousName.entries(attributes),
                nowUnixSeconds.toULong(),
            )
        } catch (_: Exception) {
            false
        }
}

/**
 * Watches the stream service while the requester holds its pairing
 * (discovery hierarchy section 5.2): every resolved instance is reported
 * with its endpoint and TXT attributes, and every vanished one is
 * reported lost. Resolves repeat while an instance stays, so a record the
 * custodian replaced in place, its withdrawn record among it, is seen.
 *
 * The watcher names no peer: instances are random, and only the requester's
 * own pairing classifies them.
 */
internal class RappRequesterDiscovery(
    private val context: Context,
    private val scope: CoroutineScope,
    private val onEvent: (Event) -> Unit,
) : AutoCloseable {
    /** What the watch reports. */
    sealed interface Event {
        /** The service [instance] resolved to [host]:[port] with [attributes]. */
        data class Resolved(
            val instance: String,
            val host: String,
            val port: Int,
            val attributes: Map<String, ByteArray?>,
        ) : Event

        /** The service [instance] vanished. */
        data class Lost(
            val instance: String,
        ) : Event
    }

    private val nsdManager = context.getSystemService(Context.NSD_SERVICE) as? NsdManager
    private val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
    private val multicastLock =
        wifiManager?.createMulticastLock("refineid-requester-discovery")?.apply {
            setReferenceCounted(false)
        }

    private var discoveryListener: NsdManager.DiscoveryListener? = null
    private var pollJob: Job? = null
    private val resolving = HashSet<String>()
    private val resolveLock = Any()
    private var closed = false

    /** The instances seen, by name, with their last found service. */
    private val known = HashMap<String, NsdServiceInfo>()
    private val knownLock = Any()

    fun start() {
        synchronized(knownLock) {
            if (closed) return
        }
        try {
            multicastLock?.acquire()
        } catch (_: Exception) {
        }
        startDiscovery()
        pollJob =
            scope.launch(Dispatchers.IO) {
                while (isActive && !isClosed()) {
                    delay(RESOLVE_POLL_MS)
                    if (isClosed()) break
                    val services =
                        synchronized(knownLock) {
                            known.values.toList()
                        }
                    services.forEach(::resolve)
                }
            }
    }

    private fun isClosed(): Boolean = synchronized(knownLock) { closed }

    private fun startDiscovery() {
        if (isClosed()) return
        val listener =
            object : NsdManager.DiscoveryListener {
                override fun onDiscoveryStarted(regType: String) {
                    trace("discovery started")
                }

                override fun onDiscoveryStopped(serviceType: String) {
                    trace("discovery stopped")
                }

                override fun onStartDiscoveryFailed(
                    serviceType: String,
                    errorCode: Int,
                ) {
                    trace("discovery failed to start: $errorCode")
                    restartLater()
                }

                override fun onStopDiscoveryFailed(
                    serviceType: String,
                    errorCode: Int,
                ) {
                    trace("discovery failed to stop: $errorCode")
                }

                override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                    remember(serviceInfo)
                    resolve(serviceInfo)
                }

                override fun onServiceLost(serviceInfo: NsdServiceInfo) {
                    forget(serviceInfo.serviceName)
                    onEvent(Event.Lost(serviceInfo.serviceName))
                }
            }
        discoveryListener = listener
        try {
            nsdManager?.discoverServices(
                StreamRelayListener.SERVICE_TYPE,
                NsdManager.PROTOCOL_DNS_SD,
                listener,
            )
        } catch (e: Exception) {
            trace("discoverServices error: ${e.javaClass.simpleName}")
            restartLater()
        }
    }

    private fun remember(serviceInfo: NsdServiceInfo) {
        synchronized(knownLock) { known[serviceInfo.serviceName] = serviceInfo }
    }

    private fun forget(instance: String) {
        synchronized(knownLock) { known.remove(instance) }
    }

    /** Restarts a failed discovery after a wait, while the watch runs. */
    private fun restartLater() {
        scope.launch(Dispatchers.IO) {
            delay(DISCOVERY_RETRY_MS)
            if (isClosed()) return@launch
            stopDiscovery()
            startDiscovery()
        }
    }

    private fun resolve(serviceInfo: NsdServiceInfo) {
        if (isClosed()) return
        synchronized(resolveLock) {
            if (!resolving.add(serviceInfo.serviceName)) return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            try {
                val callback =
                    object : NsdManager.ServiceInfoCallback {
                        override fun onServiceInfoCallbackRegistrationFailed(errorCode: Int) {
                            trace("resolve registration failed: $errorCode")
                            endResolve(serviceInfo.serviceName)
                            resolveLegacy(serviceInfo)
                        }

                        override fun onServiceUpdated(resolved: NsdServiceInfo) {
                            endResolve(serviceInfo.serviceName)
                            consider(resolved)
                        }

                        override fun onServiceLost() {
                            endResolve(serviceInfo.serviceName)
                        }

                        override fun onServiceInfoCallbackUnregistered() {
                            endResolve(serviceInfo.serviceName)
                        }
                    }
                nsdManager?.registerServiceInfoCallback(serviceInfo, context.mainExecutor, callback)
                scope.launch(Dispatchers.IO) {
                    delay(RESOLVE_TIMEOUT_MS)
                    try {
                        nsdManager?.unregisterServiceInfoCallback(callback)
                    } catch (_: Exception) {
                    }
                    endResolve(serviceInfo.serviceName)
                }
                return
            } catch (e: Exception) {
                trace("resolve registration error: ${e.javaClass.simpleName}")
            }
        }
        resolveLegacy(serviceInfo)
    }

    private fun endResolve(instance: String) {
        synchronized(resolveLock) { resolving.remove(instance) }
    }

    private fun resolveLegacy(serviceInfo: NsdServiceInfo) {
        if (isClosed()) {
            endResolve(serviceInfo.serviceName)
            return
        }
        try {
            nsdManager?.resolveService(
                serviceInfo,
                object : NsdManager.ResolveListener {
                    override fun onResolveFailed(
                        serviceInfo: NsdServiceInfo,
                        errorCode: Int,
                    ) {
                        trace("resolve failed: $errorCode")
                        endResolve(serviceInfo.serviceName)
                    }

                    override fun onServiceResolved(resolved: NsdServiceInfo) {
                        endResolve(serviceInfo.serviceName)
                        consider(resolved)
                    }
                },
            )
        } catch (e: Exception) {
            trace("resolve error: ${e.javaClass.simpleName}")
            endResolve(serviceInfo.serviceName)
        }
    }

    private fun consider(resolved: NsdServiceInfo) {
        if (isClosed()) return
        remember(resolved)
        val host =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                resolved.hostAddresses.firstOrNull()?.hostAddress ?: resolved.host?.hostAddress
            } else {
                resolved.host?.hostAddress
            } ?: return
        if (resolved.port <= 0) return
        onEvent(Event.Resolved(resolved.serviceName, host, resolved.port, resolved.attributes))
    }

    private fun stopDiscovery() {
        discoveryListener?.let {
            try {
                nsdManager?.stopServiceDiscovery(it)
            } catch (_: Exception) {
            }
        }
        discoveryListener = null
    }

    override fun close() {
        synchronized(knownLock) {
            if (closed) return
            closed = true
        }
        pollJob?.cancel()
        pollJob = null
        stopDiscovery()
        try {
            multicastLock?.release()
        } catch (_: Exception) {
        }
    }

    private fun trace(message: String) {
        if (BuildConfig.DEBUG) {
            android.util.Log.d(TRACE_TAG, message)
        }
    }

    private companion object {
        const val TRACE_TAG = "REQUESTER_DISCOVERY"

        /** How often every known instance is resolved again, so replaced records are seen. */
        const val RESOLVE_POLL_MS = 2_000L

        /** How long one resolve may take before its callback is dropped. */
        const val RESOLVE_TIMEOUT_MS = 5_000L

        /** How long a failed discovery waits before it starts again. */
        const val DISCOVERY_RETRY_MS = 10_000L
    }
}
