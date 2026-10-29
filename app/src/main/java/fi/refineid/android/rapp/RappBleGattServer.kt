// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.ParcelUuid
import androidx.core.content.ContextCompat
import fi.refineid.android.diagnostics.AppTrace
import java.util.UUID
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** A step of the Bluetooth server, for the debug trace. */
internal enum class RappBleServerStep(
    /** Whether the step is a failure the debug build shows as an error. */
    val isFailure: Boolean,
) {
    SERVICE_PUBLISHED(false),
    SERVICE_NOT_PUBLISHED(true),
    ADVERTISING_STARTED(false),
    ADVERTISING_STOPPED(false),
    ADVERTISING_FAILED(true),
    ADVERTISING_UNSUPPORTED(true),
    RADIO_ON(false),
    RADIO_OFF(true),
    BLUETOOTH_UNSUPPORTED(true),
    PERMISSION_MISSING(true),
    PERMISSION_DENIED(true),
}

/**
 * The custodian's GATT server of `fi.refineid.rapp.ble` (RAPP v26.10.29
 * section 5): the RAPP service published once, the advertisement carrying
 * only its UUID, and one link per subscribed central, kept by
 * [RappBleGattLinks].
 *
 * The advertisement carries no device name and nothing derived from a
 * pairing (section 4.1). The characteristics need no link-layer security, so
 * no central's system ever asks to bond (STPA CC-54). Bluetooth turning off
 * ends every link and the service; turning on publishes and advertises again.
 * The server runs inside the custodian's foreground service, which keeps the
 * process out of the cached state, so Doze and app standby leave the
 * advertisement and the GATT callbacks running.
 *
 * Every platform callback and every public call runs on one lane, the
 * server's own thread; [admits] and [onEvent] are called there.
 */
internal class RappBleGattServer(
    private val context: Context,
    admits: (preamble: ByteArray, link: RappBleLink) -> Boolean,
    onEvent: (RappBleGattEvent) -> Unit,
) {
    private val lane =
        ScheduledThreadPoolExecutor(LANE_THREADS) { runnable -> Thread(runnable, LANE_NAME) }.apply {
            // A shut-down server runs none of its timers.
            executeExistingDelayedTasksAfterShutdownPolicy = false
        }
    private val manager: BluetoothManager? = context.getSystemService(BluetoothManager::class.java)
    private var gatt: BluetoothGattServer? = null
    private var channel: BluetoothGattCharacteristic? = null
    private var serving = false
    private var advertisingWanted = true
    private var advertising = false

    private val port =
        object : RappBleGattPort<BluetoothDevice> {
            override fun indicate(
                device: BluetoothDevice,
                fragment: ByteArray,
            ): Boolean = indicateOn(device, fragment)

            override fun schedule(
                delayMs: Long,
                action: () -> Unit,
            ) {
                post(delayMs, action)
            }

            override fun nowMs(): ULong = RappClock.monotonicMs()
        }

    private val links = RappBleGattLinks(port, admits, onEvent)

    private val callback =
        object : BluetoothGattServerCallback() {
            override fun onConnectionStateChange(
                device: BluetoothDevice,
                status: Int,
                newState: Int,
            ) {
                if (newState == BluetoothProfile.STATE_DISCONNECTED) post { links.disconnected(device) }
            }

            override fun onMtuChanged(
                device: BluetoothDevice,
                mtu: Int,
            ) {
                post { links.mtuChanged(device, mtu) }
            }

            override fun onServiceAdded(
                status: Int,
                service: BluetoothGattService,
            ) {
                post { serviceAdded(status == BluetoothGatt.GATT_SUCCESS) }
            }

            override fun onCharacteristicWriteRequest(
                device: BluetoothDevice,
                requestId: Int,
                characteristic: BluetoothGattCharacteristic,
                preparedWrite: Boolean,
                responseNeeded: Boolean,
                offset: Int,
                value: ByteArray?,
            ) {
                val attribute = attributeOf(characteristic.uuid)
                post {
                    links.write(
                        RappBleWrite(device, attribute, !preparedWrite && offset == 0, responseNeeded, value) {
                            respond(device, requestId, it, offset, null)
                        },
                    )
                }
            }

            override fun onDescriptorWriteRequest(
                device: BluetoothDevice,
                requestId: Int,
                descriptor: BluetoothGattDescriptor,
                preparedWrite: Boolean,
                responseNeeded: Boolean,
                offset: Int,
                value: ByteArray?,
            ) {
                val attribute = attributeOf(descriptor)
                post {
                    links.write(
                        RappBleWrite(device, attribute, !preparedWrite && offset == 0, responseNeeded, value) {
                            respond(device, requestId, it, offset, null)
                        },
                    )
                }
            }

            override fun onCharacteristicReadRequest(
                device: BluetoothDevice,
                requestId: Int,
                offset: Int,
                characteristic: BluetoothGattCharacteristic,
            ) {
                val attribute = attributeOf(characteristic.uuid)
                post {
                    links.read(
                        RappBleRead(device, attribute, offset) { answer, value ->
                            respond(device, requestId, answer, offset, value)
                        },
                    )
                }
            }

            override fun onDescriptorReadRequest(
                device: BluetoothDevice,
                requestId: Int,
                offset: Int,
                descriptor: BluetoothGattDescriptor,
            ) {
                val attribute = attributeOf(descriptor)
                post {
                    links.read(
                        RappBleRead(device, attribute, offset) { answer, value ->
                            respond(device, requestId, answer, offset, value)
                        },
                    )
                }
            }

            override fun onExecuteWrite(
                device: BluetoothDevice,
                requestId: Int,
                execute: Boolean,
            ) {
                // The profile takes no prepared write, so there is nothing to execute.
                post { respond(device, requestId, RappBleAttAnswer.WRITE_NOT_PERMITTED, 0, null) }
            }

            override fun onNotificationSent(
                device: BluetoothDevice,
                status: Int,
            ) {
                post { links.notificationSent(device, status == BluetoothGatt.GATT_SUCCESS) }
            }
        }

    private val advertiseCallback =
        object : AdvertiseCallback() {
            override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
                post { AppTrace.rappBleServer(RappBleServerStep.ADVERTISING_STARTED) }
            }

            override fun onStartFailure(errorCode: Int) {
                post { advertisingFailed(errorCode) }
            }
        }

    private val radioReceiver =
        object : BroadcastReceiver() {
            override fun onReceive(
                context: Context,
                intent: Intent,
            ) {
                val state = intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)
                post { radioChanged(state) }
            }
        }

    /** Publishes and advertises, now or once Bluetooth turns on. */
    fun start() {
        post {
            if (serving) return@post
            serving = true
            ContextCompat.registerReceiver(
                context,
                radioReceiver,
                IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED),
                ContextCompat.RECEIVER_NOT_EXPORTED,
            )
            open()
        }
    }

    /** Indicates one frame on [link]. */
    fun send(
        link: RappBleLink,
        frame: ByteArray,
    ) {
        post { links.send(link, frame) }
    }

    /** Ends [link] once what it already queued is indicated. */
    fun close(link: RappBleLink) {
        post { links.close(link) }
    }

    /** Stops advertising for good; open links keep serving until [cancel]. */
    fun stopAdvertising() {
        post {
            advertisingWanted = false
            stopAdvertisingNow()
        }
    }

    /** Stops advertising, ends every link once its queued frames are out, and closes the server. */
    fun cancel() {
        post {
            if (!serving) return@post
            serving = false
            try {
                context.unregisterReceiver(radioReceiver)
            } catch (_: IllegalArgumentException) {
                // Never registered.
            }
            stopAdvertisingNow()
            links.shutdown {
                closeGatt()
                lane.shutdown()
            }
        }
    }

    private fun post(action: () -> Unit) {
        try {
            lane.execute(action)
        } catch (_: RejectedExecutionException) {
            // The server is shut down.
        }
    }

    private fun post(
        delayMs: Long,
        action: () -> Unit,
    ) {
        try {
            lane.schedule(action, delayMs, TimeUnit.MILLISECONDS)
        } catch (_: RejectedExecutionException) {
            // The server is shut down.
        }
    }

    /** Opens the server and adds the RAPP service; advertising follows once the system added it. */
    private fun open() {
        if (!serving || gatt != null) return
        val manager = manager
        val adapter = manager?.adapter
        val unavailable =
            when {
                !permitted(context) -> RappBleServerStep.PERMISSION_MISSING
                adapter == null || !supported(context) -> RappBleServerStep.BLUETOOTH_UNSUPPORTED
                !adapter.isEnabled -> RappBleServerStep.RADIO_OFF
                else -> null
            }
        if (unavailable != null || manager == null) {
            AppTrace.rappBleServer(unavailable ?: RappBleServerStep.BLUETOOTH_UNSUPPORTED)
            return
        }
        val server =
            try {
                manager.openGattServer(context, callback)
            } catch (_: SecurityException) {
                null
            }
        if (server == null) {
            AppTrace.rappBleServer(RappBleServerStep.SERVICE_NOT_PUBLISHED)
            return
        }
        gatt = server
        channel = addRappService(server)
        if (channel == null) {
            AppTrace.rappBleServer(RappBleServerStep.SERVICE_NOT_PUBLISHED)
            closeGatt()
        }
    }

    private fun serviceAdded(added: Boolean) {
        if (!added) {
            AppTrace.rappBleServer(RappBleServerStep.SERVICE_NOT_PUBLISHED)
            closeGatt()
            return
        }
        AppTrace.rappBleServer(RappBleServerStep.SERVICE_PUBLISHED)
        advertise()
    }

    /** Advertises the service UUID alone: no name, no power level, nothing of a pairing (section 4.1). */
    private fun advertise() {
        if (!serving || !advertisingWanted || advertising || gatt == null) return
        val advertiser = manager?.adapter?.bluetoothLeAdvertiser
        if (advertiser == null) {
            AppTrace.rappBleServer(RappBleServerStep.ADVERTISING_UNSUPPORTED)
            return
        }
        val settings =
            AdvertiseSettings
                .Builder()
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_BALANCED)
                .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
                .setConnectable(true)
                .setTimeout(ADVERTISE_WITHOUT_TIMEOUT)
                .build()
        val data =
            AdvertiseData
                .Builder()
                .addServiceUuid(ParcelUuid(RappBleGattProfile.SERVICE_UUID))
                .setIncludeDeviceName(false)
                .setIncludeTxPowerLevel(false)
                .build()
        try {
            advertiser.startAdvertising(settings, data, advertiseCallback)
            advertising = true
        } catch (_: SecurityException) {
            AppTrace.rappBleServer(RappBleServerStep.PERMISSION_MISSING)
        }
    }

    /**
     * Advertising did not start. Running out of advertising sets, or an
     * internal failure, is retried after [ADVERTISING_RETRY_MS] while the
     * server serves.
     */
    private fun advertisingFailed(errorCode: Int) {
        if (errorCode == AdvertiseCallback.ADVERTISE_FAILED_ALREADY_STARTED) return
        advertising = false
        AppTrace.rappBleServer(RappBleServerStep.ADVERTISING_FAILED, errorCode)
        if (errorCode in RETRIED_ADVERTISING_FAILURES) post(ADVERTISING_RETRY_MS) { advertise() }
    }

    private fun stopAdvertisingNow() {
        if (!advertising) return
        advertising = false
        try {
            manager?.adapter?.bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback)
        } catch (_: SecurityException) {
            // The process loses the permission only by being killed.
        }
        AppTrace.rappBleServer(RappBleServerStep.ADVERTISING_STOPPED)
    }

    private fun radioChanged(state: Int) {
        when (state) {
            BluetoothAdapter.STATE_ON -> {
                AppTrace.rappBleServer(RappBleServerStep.RADIO_ON)
                open()
            }

            BluetoothAdapter.STATE_TURNING_OFF, BluetoothAdapter.STATE_OFF -> {
                if (gatt == null) return
                AppTrace.rappBleServer(RappBleServerStep.RADIO_OFF)
                links.radioDown()
                advertising = false
                closeGatt()
            }
        }
    }

    private fun closeGatt() {
        stopAdvertisingNow()
        val server = gatt ?: return
        gatt = null
        channel = null
        try {
            server.close()
        } catch (_: SecurityException) {
            // The process loses the permission only by being killed.
        }
    }

    private fun indicateOn(
        device: BluetoothDevice,
        fragment: ByteArray,
    ): Boolean {
        val server = gatt ?: return false
        val characteristic = channel ?: return false
        return try {
            server.notifyCharacteristicChanged(device, characteristic, INDICATE, fragment) ==
                BluetoothStatusCodes.SUCCESS
        } catch (_: SecurityException) {
            false
        } catch (_: IllegalArgumentException) {
            false
        }
    }

    private fun respond(
        device: BluetoothDevice,
        requestId: Int,
        answer: RappBleAttAnswer,
        offset: Int,
        value: ByteArray?,
    ) {
        val server = gatt ?: return
        val status =
            when (answer) {
                RappBleAttAnswer.SUCCESS -> BluetoothGatt.GATT_SUCCESS
                RappBleAttAnswer.WRITE_NOT_PERMITTED -> BluetoothGatt.GATT_WRITE_NOT_PERMITTED
                RappBleAttAnswer.READ_NOT_PERMITTED -> BluetoothGatt.GATT_READ_NOT_PERMITTED
            }
        try {
            server.sendResponse(device, requestId, status, offset, value)
        } catch (_: SecurityException) {
            // The process loses the permission only by being killed.
        }
    }

    companion object {
        private const val LANE_NAME = "rapp-ble-gatt"
        private const val LANE_THREADS = 1

        /** Indications, confirmed by the central, never notifications (section 5.2). */
        private const val INDICATE = true

        /** Advertising runs until stopped. */
        private const val ADVERTISE_WITHOUT_TIMEOUT = 0

        /** How long to wait before advertising again after a failure that may pass. */
        private const val ADVERTISING_RETRY_MS = 30_000L

        private val RETRIED_ADVERTISING_FAILURES =
            setOf(
                AdvertiseCallback.ADVERTISE_FAILED_TOO_MANY_ADVERTISERS,
                AdvertiseCallback.ADVERTISE_FAILED_INTERNAL_ERROR,
            )

        /** The runtime permissions serving over Bluetooth needs (Android 12 and newer). */
        val PERMISSIONS: List<String> =
            listOf(Manifest.permission.BLUETOOTH_ADVERTISE, Manifest.permission.BLUETOOTH_CONNECT)

        /** Whether the holder granted [PERMISSIONS]. */
        fun permitted(context: Context): Boolean =
            PERMISSIONS.all { ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED }

        private fun supported(context: Context): Boolean =
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE)

        private fun attributeOf(uuid: UUID): RappBleAttribute =
            when (uuid) {
                RappBleGattProfile.CHANNEL_UUID -> RappBleAttribute.CHANNEL
                RappBleGattProfile.BOOTSTRAP_UUID -> RappBleAttribute.BOOTSTRAP
                else -> RappBleAttribute.OTHER
            }

        private fun attributeOf(descriptor: BluetoothGattDescriptor): RappBleAttribute =
            if (descriptor.uuid == RappBleGattProfile.CCCD_UUID &&
                descriptor.characteristic?.uuid == RappBleGattProfile.CHANNEL_UUID
            ) {
                RappBleAttribute.CHANNEL_CCCD
            } else {
                RappBleAttribute.OTHER
            }
    }
}

/**
 * Adds the RAPP service to [server] (RAPP v26.10.29 section 5.1) and returns
 * its channel characteristic, or null when the platform refused. Every
 * attribute is a plain read or write: none asks for encryption or
 * authentication (STPA CC-54).
 */
private fun addRappService(server: BluetoothGattServer): BluetoothGattCharacteristic? {
    val service = BluetoothGattService(RappBleGattProfile.SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
    val channel =
        BluetoothGattCharacteristic(
            RappBleGattProfile.CHANNEL_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_INDICATE,
            BluetoothGattCharacteristic.PERMISSION_WRITE,
        )
    channel.addDescriptor(
        BluetoothGattDescriptor(
            RappBleGattProfile.CCCD_UUID,
            BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE,
        ),
    )
    service.addCharacteristic(channel)
    service.addCharacteristic(
        BluetoothGattCharacteristic(
            RappBleGattProfile.BOOTSTRAP_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ,
        ),
    )
    val added =
        try {
            server.addService(service)
        } catch (_: SecurityException) {
            false
        }
    return channel.takeIf { added }
}
