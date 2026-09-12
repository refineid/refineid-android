package fi.refineid.android.diagnostics

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import fi.refineid.android.BuildConfig
import fi.refineid.android.RefineIdApplication
import java.io.File

/**
 * Debug-only BroadcastReceiver for extracting plaintext diagnostics from the phone.
 * Compiled exclusively into debug builds; completely absent from release builds.
 */
class DiagnosticsDumpReceiver : BroadcastReceiver() {
    override fun onReceive(
        context: Context,
        intent: Intent,
    ) {
        if (!BuildConfig.DEBUG) return

        when (intent.action) {
            ACTION_CLEAR_LOGS -> {
                AppTrace.clearTraceLog()
                if (BuildConfig.DEBUG) {
                    Log.i(TAG, "AppTrace log cleared via broadcast")
                }
                resultData = "LOGS_CLEARED"
            }

            ACTION_DUMP_DIAGNOSTICS, null -> {
                val app = context.applicationContext as? RefineIdApplication
                val nfcSnapshot = app?.nfcReaderController?.snapshot
                val usbSnapshot = app?.readerController?.snapshot
                val holder = nfcSnapshot?.holderName ?: usbSnapshot?.holderName
                val details = nfcSnapshot?.cardDetails ?: usbSnapshot?.cardDetails

                val pairs = app?.rappPairCatalog?.listPairs() ?: emptyList()
                val pairSummary =
                    if (pairs.isEmpty()) {
                        "  (none)"
                    } else {
                        pairs.joinToString("\n") { p ->
                            "  - ${p.displayName} [${p.platform}] id=${p.pairIdHex.take(
                                8,
                            )}... cert=${p.certificateDerBase64 != null}"
                        }
                    }
                val rappStatus =
                    "Listener Port: ${app?.rappProxyDispatcher?.listeningPort ?: "inactive"}\n" +
                        "Connected Peer: ${app
                            ?.rappProxyDispatcher
                            ?.connectedPeer
                            ?.value
                            ?.displayName ?: "none"}\n" +
                        "Paired Devices (${pairs.size}):\n$pairSummary"

                val snapshot =
                    DiagnosticsCollector.collect(
                        context = context,
                        nfcReaderStatus = nfcSnapshot?.status,
                        usbReaderStatus = usbSnapshot?.status,
                        holderName = holder,
                        cardDetails = details,
                        rappStatus = rappStatus,
                    )

                val report = snapshot.toReportText()

                // 1. Write to internal cache
                try {
                    File(context.cacheDir, DIAGNOSTICS_FILENAME).writeText(report)
                } catch (_: Exception) {
                }

                // 2. Also write to external files dir if available
                try {
                    context.getExternalFilesDir(null)?.let { externalDir ->
                        File(externalDir, DIAGNOSTICS_FILENAME).writeText(report)
                    }
                } catch (_: Exception) {
                }

                // 3. Log to logcat under dedicated unflooded tag in chunks
                if (BuildConfig.DEBUG) {
                    for (chunk in report.lines().chunked(LOGCAT_CHUNK_LINES)) {
                        if (BuildConfig.DEBUG) {
                            Log.i(TAG, chunk.joinToString("\n"))
                        }
                    }

                    val msg = "DUMP_OK: ${snapshot.traceLogs.size} trace lines written to files/$DIAGNOSTICS_FILENAME"
                    Log.i(TAG, msg)
                    resultData = msg
                }
            }
        }
    }

    companion object {
        const val ACTION_DUMP_DIAGNOSTICS = "fi.refineid.android.DUMP_DIAGNOSTICS"
        const val ACTION_CLEAR_LOGS = "fi.refineid.android.CLEAR_LOGS"
        private const val TAG = "RefineIdDiag"
        private const val DIAGNOSTICS_FILENAME = "diagnostics.txt"
        private const val LOGCAT_CHUNK_LINES = 50
    }
}
