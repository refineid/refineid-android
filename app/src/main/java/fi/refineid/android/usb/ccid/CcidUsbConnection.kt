package fi.refineid.android.usb.ccid

import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbInterface
import fi.refineid.android.diagnostics.AppTrace

internal data class CcidUsbEndpoints(
    val usbInterface: UsbInterface,
    val bulkIn: UsbEndpoint,
    val bulkOut: UsbEndpoint,
    val interruptIn: UsbEndpoint? = null,
)

internal object CcidUsbEndpointFinder {
    /**
     * Every CCID-class interface with a bulk pair, in descriptor order. A
     * multi-slot reader exposes one CCID interface per slot (a dual reader
     * typically lists the contactless PICC first, then the contact ICC,
     * then a SAM), so a session opener must probe each interface for a
     * card instead of assuming the first one owns the only slot.
     */
    fun findAll(device: UsbDevice): List<CcidUsbEndpoints> {
        val candidates = mutableListOf<CcidUsbEndpoints>()
        repeat(device.interfaceCount) { interfaceIndex ->
            val usbInterface = device.getInterface(interfaceIndex)
            if (usbInterface.interfaceClass != UsbConstants.USB_CLASS_CSCID) {
                return@repeat
            }

            var bulkIn: UsbEndpoint? = null
            var bulkOut: UsbEndpoint? = null
            var interruptIn: UsbEndpoint? = null
            repeat(usbInterface.endpointCount) { endpointIndex ->
                val endpoint = usbInterface.getEndpoint(endpointIndex)
                when (endpoint.type) {
                    UsbConstants.USB_ENDPOINT_XFER_BULK -> {
                        when (endpoint.direction) {
                            UsbConstants.USB_DIR_IN -> bulkIn = endpoint
                            UsbConstants.USB_DIR_OUT -> bulkOut = endpoint
                        }
                    }

                    UsbConstants.USB_ENDPOINT_XFER_INT -> {
                        if (endpoint.direction == UsbConstants.USB_DIR_IN) {
                            interruptIn = endpoint
                        }
                    }
                }
            }

            val foundIn = bulkIn
            val foundOut = bulkOut
            if (foundIn != null && foundOut != null) {
                candidates.add(
                    CcidUsbEndpoints(
                        usbInterface = usbInterface,
                        bulkIn = foundIn,
                        bulkOut = foundOut,
                        interruptIn = interruptIn,
                    ),
                )
            }
        }

        return candidates
    }
}

/**
 * How one host-to-reader bulk transfer ended. An outbound frame may carry a
 * credential, and the transport cannot tell which one does, so this outcome
 * stands in for every outbound byte count: a frame size would disclose the
 * credential length.
 */
internal enum class CcidBulkOutOutcome {
    COMPLETE,
    SHORT,
    FAILED,
    ;

    companion object {
        fun of(
            requested: Int,
            transferred: Int,
        ): CcidBulkOutOutcome =
            when {
                transferred < 0 -> FAILED
                transferred == requested -> COMPLETE
                else -> SHORT
            }
    }
}

internal class AndroidCcidBulkIo(
    private val connection: UsbDeviceConnection,
    private val endpoints: CcidUsbEndpoints,
) : CcidBulkIo {
    override fun write(frame: ByteArray): Int =
        transfer(
            endpoint = endpoints.bulkOut,
            frame = frame,
        ).also { transferred ->
            AppTrace.ccidBulkOut(
                CcidBulkOutOutcome.of(
                    requested = frame.size,
                    transferred = transferred,
                ),
            )
        }

    // The capacity is the fixed response buffer. The count is a reader
    // response frame: the card answers a credential command with a status
    // word and no data derived from the credential, so the inbound size
    // does not depend on the credential length.
    override fun read(frame: ByteArray): Int =
        transfer(
            endpoint = endpoints.bulkIn,
            frame = frame,
        ).also { transferred ->
            AppTrace.ccidBulkIn(
                capacity = frame.size,
                transferred = transferred,
            )
        }

    private fun transfer(
        endpoint: UsbEndpoint,
        frame: ByteArray,
    ): Int =
        try {
            connection.bulkTransfer(
                endpoint,
                frame,
                0,
                frame.size,
                USB_TRANSFER_TIMEOUT_MILLISECONDS,
            )
        } catch (_: SecurityException) {
            -1
        }

    private companion object {
        const val USB_TRANSFER_TIMEOUT_MILLISECONDS = 2_000
    }
}
