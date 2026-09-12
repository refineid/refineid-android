package fi.refineid.android.diagnostics

import android.content.Context
import android.hardware.usb.UsbManager
import android.nfc.NfcAdapter
import android.os.Build
import fi.refineid.android.BuildConfig
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
        holderName: String? = null,
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

        val cardStatus =
            buildString {
                appendLine("Holder: ${holderName ?: "(none)"}")
                appendLine("Document Number: ${cardDetails?.documentNumber ?: "(none)"}")
                appendLine("Valid: ${cardDetails?.issuedDate ?: "?"} .. ${cardDetails?.expiryDate ?: "?"}")
                appendLine("Issuer: ${cardDetails?.issuer ?: "(none)"}")
                appendLine("Generation: ${cardGenerationLabel(cardDetails?.issuedDate)}")
                appendLine("Signature Algorithm: ${cardDetails?.signatureAlgorithm ?: "(unknown)"}")
                appendLine("Tamper-Proof Verified: ${cardDetails?.isTamperProofVerified ?: false}")
            }.trimEnd()

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
 * Card generation from the authentication certificate's issued date
 * (FINEID S4-1 section 4.6; DVV cutover 13 January 2026). Cards issued
 * from that date use the preset activation PIN; older cards use the PUK
 * as the activation code. The date arrives formatted as d.M.yyyy.
 */
internal fun cardGenerationLabel(issuedDate: String?): String {
    if (issuedDate == null) return "unknown (no issue date)"
    val parts = issuedDate.split(".")
    if (parts.size != DATE_PART_COUNT) return "unknown (unparseable issue date)"
    val day = parts[0].toIntOrNull()
    val month = parts[1].toIntOrNull()
    val year = parts[2].toIntOrNull()
    if (day == null || month == null || year == null) return "unknown (unparseable issue date)"
    val onOrAfterCutover =
        year > CUTOVER_YEAR ||
            (
                year == CUTOVER_YEAR &&
                    (
                        month > CUTOVER_MONTH ||
                            (month == CUTOVER_MONTH && day >= CUTOVER_DAY)
                    )
            )
    val isNewer = onOrAfterCutover
    return if (isNewer) {
        "Newer (preset activation PIN, issued on/after 13.1.2026)"
    } else {
        "Older (PUK activation code, issued before 13.1.2026)"
    }
}

private const val DATE_PART_COUNT = 3
private const val CUTOVER_YEAR = 2026
private const val CUTOVER_MONTH = 1
private const val CUTOVER_DAY = 13
