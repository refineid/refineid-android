package fi.refineid.android.diagnostics

import android.content.Context
import android.hardware.usb.UsbManager
import android.nfc.NfcAdapter
import android.os.Build
import fi.refineid.android.BuildConfig
import fi.refineid.android.core.CardManagementScheme
import fi.refineid.android.core.CredentialHealth
import fi.refineid.android.core.NativePinReferenceScheme
import fi.refineid.android.core.ObservedCredentialHealth
import fi.refineid.android.core.PersonCardDetails
import fi.refineid.android.nfc.NfcReaderStatus
import fi.refineid.android.usb.ReaderConnectionStatus

internal data class DiagnosticsSnapshot(
    val appInfo: String,
    val deviceInfo: String,
    val nfcStatus: String,
    val usbStatus: String,
    val cardStatus: String,
    val rappStatus: String? = null,
    val traceLogs: List<String>,
) {
    fun toReportText(): String =
        buildString {
            appendLine("== RefineID Android Diagnostics ==")
            appendLine()
            appendLine("== Application ==")
            appendLine(appInfo)
            appendLine()
            appendLine("== Device ==")
            appendLine(deviceInfo)
            appendLine()
            appendLine("== NFC ==")
            appendLine(nfcStatus)
            appendLine()
            appendLine("== USB CCID ==")
            appendLine(usbStatus)
            appendLine()
            appendLine("== Card & Identity ==")
            appendLine(cardStatus)
            appendLine()
            if (!rappStatus.isNullOrBlank()) {
                appendLine("== Remote Access (RAPP) ==")
                appendLine(rappStatus)
                appendLine()
            }
            appendLine("== Trace Log (${traceLogs.size} lines) ==")
            if (traceLogs.isEmpty()) {
                appendLine("(no trace events recorded)")
            } else {
                traceLogs.forEach { appendLine(it) }
            }
        }
}

internal object DiagnosticsCollector {
    fun collect(
        context: Context,
        nfcReaderStatus: NfcReaderStatus? = null,
        usbReaderStatus: ReaderConnectionStatus? = null,
        cardDetails: PersonCardDetails? = null,
        rappStatus: String? = null,
    ): DiagnosticsSnapshot {
        val appInfo =
            "Version: ${BuildConfig.VERSION_NAME} (${BuildConfig.BUILD_NUMBER})\n" +
                "Package: ${context.packageName}\n" +
                "Build type: ${BuildConfig.BUILD_TYPE}"

        val deviceInfo =
            "Device: ${Build.MANUFACTURER} ${Build.MODEL} (${Build.PRODUCT})\n" +
                "Android: ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})\n" +
                "Hardware: ${Build.HARDWARE}, Board: ${Build.BOARD}"

        val nfcAdapter = NfcAdapter.getDefaultAdapter(context)
        val nfcStatus =
            if (nfcAdapter == null) {
                "NFC Adapter: Not available"
            } else {
                "NFC Adapter: Present, Enabled: ${nfcAdapter.isEnabled}\n" +
                    "Reader Status: ${nfcReaderStatus ?: "Unknown"}"
            }

        val usbManager = context.getSystemService(Context.USB_SERVICE) as? UsbManager
        val usbDevices =
            usbManager
                ?.deviceList
                ?.values
                ?.toList()
                .orEmpty()
        val usbStatus =
            buildString {
                appendLine("Attached USB Devices: ${usbDevices.size}")
                appendLine("USB Reader Status: ${usbReaderStatus ?: "Unknown"}")
                usbDevices.forEachIndexed { index, dev ->
                    val hasPerm = usbManager?.hasPermission(dev) == true
                    val vidHex = dev.vendorId.toString(HEX_RADIX).padStart(HEX_DIGITS_SHORT, '0')
                    val pidHex = dev.productId.toString(HEX_RADIX).padStart(HEX_DIGITS_SHORT, '0')
                    appendLine(
                        "  [$index] ${dev.manufacturerName ?: "Unknown"} ${dev.productName ?: "Device"} " +
                            "(VID: 0x$vidHex, PID: 0x$pidHex, Permission: $hasPerm)",
                    )
                }
            }.trimEnd()

        val cardStatus = cardStatusText(cardDetails, ObservedCredentialHealth.latest)

        return DiagnosticsSnapshot(
            appInfo = appInfo,
            deviceInfo = deviceInfo,
            nfcStatus = nfcStatus,
            usbStatus = usbStatus,
            cardStatus = cardStatus,
            rappStatus = rappStatus,
            traceLogs = AppTrace.getTraceLog(),
        )
    }

    private const val HEX_RADIX = 16
    private const val HEX_DIGITS_SHORT = 4
}

/**
 * Card and identity summary for diagnostics. Holder identity (name,
 * validity dates) is omitted: it identifies the holder without helping
 * a bug report. The numbering and the activation scheme are the ones the
 * native core reported at the latest credential health probe.
 */
internal fun cardStatusText(
    cardDetails: PersonCardDetails?,
    credentialHealth: CredentialHealth?,
): String =
    buildString {
        appendLine("Issuer: ${cardDetails?.issuer ?: "(none)"}")
        appendLine("Numbering: ${numberingLabel(credentialHealth)}")
        appendLine("Activation scheme: ${activationSchemeLabel(credentialHealth)}")
        appendLine("Signature Algorithm: ${cardDetails?.signatureAlgorithm ?: "(unknown)"}")
    }.trimEnd()

private fun numberingLabel(health: CredentialHealth?): String =
    when (health?.scheme) {
        null -> NOT_PROBED
        NativePinReferenceScheme.CITIZEN -> "citizen (FINEID S1)"
        NativePinReferenceScheme.ORGANIZATIONAL -> "organization (FINEID S4-2 section 4.2)"
    }

private fun activationSchemeLabel(health: CredentialHealth?): String =
    when (health?.activationScheme) {
        null -> NOT_PROBED
        CardManagementScheme.PUK -> "activation PIN is the PUK (FINEID S4-1 section 4.6.1)"
        CardManagementScheme.PRESET_PIN -> "preset activation PIN (FINEID S4-1 section 4.6.2)"
        CardManagementScheme.UNKNOWN -> "none decided"
    }

private const val NOT_PROBED = "(not probed)"
