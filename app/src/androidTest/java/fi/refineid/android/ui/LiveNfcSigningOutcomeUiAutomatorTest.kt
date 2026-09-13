package fi.refineid.android.ui

import android.content.ComponentName
import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.uiAutomator
import fi.refineid.android.RefineIdApplication
import fi.refineid.android.browser.BundledIssuerCertificates
import fi.refineid.android.core.Pin2Submission
import fi.refineid.android.document.DocumentValidationResult
import fi.refineid.android.document.DocumentValidator
import fi.refineid.android.document.PdfSignatureClaim
import fi.refineid.android.document.QualifiedPdfArchivalCompletion
import fi.refineid.android.document.QualifiedPdfArchivalFailure
import fi.refineid.android.document.QualifiedPdfArchivalResult
import fi.refineid.android.document.QualifiedPdfPreparationResult
import fi.refineid.android.document.QualifiedPdfSigningCoordinator
import fi.refineid.android.document.SignedPdfDocument
import fi.refineid.android.document.ValidationMaterialCollectionFailure
import fi.refineid.android.document.ValidationPathRole
import fi.refineid.android.settings.TimestampAuthorityConfiguration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Opt-in live check of the signing contract against whatever the card's
 * certificate status turns out to be at run time. Revocation is a fact
 * the validation services discover, never an assumption baked in here:
 * DVV centrally revoked the pre-2023 ECC signature certificates, and can
 * revoke — or issue — others at any time.
 *
 * The card-side signature must always succeed. Then exactly one of two
 * outcomes is correct, and this test accepts only the one matching the
 * discovered status:
 *  - the certificate validates → a signed document exists and its
 *    signature independently verifies over the byte range, or
 *  - the services report the certificate revoked → the flow refuses and
 *    hands out no document at all.
 * Anything else — a refusal without a named revocation, or a document
 * that fails its own verification — fails the test.
 */
@RunWith(AndroidJUnit4::class)
internal class LiveNfcSigningOutcomeUiAutomatorTest {
    @Test(timeout = LIVE_TEST_TIMEOUT_MILLISECONDS)
    fun liveSigningOutcomeMatchesTheDiscoveredCertificateStatus() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val arguments = InstrumentationRegistry.getArguments()
        assumeTrue(
            "enable the opt-in live NFC signing-outcome check",
            arguments.getString(LIVE_TEST_ARGUMENT) == LIVE_TEST_ENABLED_VALUE,
        )
        val can = arguments.getString(CAN_ARGUMENT)
        val pin2 = arguments.getString(PIN2_ARGUMENT)
        assumeTrue("supply the access number", !can.isNullOrEmpty())
        assumeTrue("supply PIN2 to sign", !pin2.isNullOrEmpty())

        val context = instrumentation.targetContext
        val application = context.applicationContext as RefineIdApplication
        context.startActivity(
            Intent
                .makeMainActivity(ComponentName(context, TARGET_ACTIVITY_CLASS))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        )
        uiAutomator {
            waitForAppToBeVisible(TARGET_PACKAGE)
            // Wait until the card is actually on the antenna, so the tap-to
            // sign session has a live tag to adopt rather than racing the
            // card's one-time recognition.
            onElement(CARD_TIMEOUT_MILLISECONDS) {
                text?.toString() == CARD_RECOGNIZED_LABEL
            }
        }

        val controller = application.nfcReaderController
        val coordinator = QualifiedPdfSigningCoordinator(controller.qualifiedCardService)
        val completion = CountDownLatch(SINGLE_COMPLETION)
        val outcome = AtomicReference<QualifiedPdfPreparationResult>()

        instrumentation.runOnMainSync {
            controller.tapToSign.begin(
                checkNotNull(can).encodeToByteArray(),
                {
                    coordinator.prepare(
                        document = minimalPdf(),
                        claim =
                            PdfSignatureClaim(
                                signedAt = Instant.now(),
                                reason = null,
                                location = null,
                            ),
                        pin2 = Pin2Submission.from(checkNotNull(pin2)),
                    ) { result ->
                        outcome.set(result)
                        controller.tapToSign.end()
                        completion.countDown()
                    }
                },
                {
                    controller.tapToSign.end()
                    completion.countDown()
                },
            )
        }
        assertTrue(
            "the card was not presented for signing in time",
            completion.await(SIGN_TIMEOUT_SECONDS, TimeUnit.SECONDS),
        )

        // The card-side signature must succeed whatever the certificate
        // status: revocation is about the certificate, not the mechanism.
        val prepared =
            when (val result = outcome.get()) {
                is QualifiedPdfPreparationResult.Success -> {
                    result.prepared
                }

                is QualifiedPdfPreparationResult.Failure -> {
                    fail("the card-side signature failed: " + result.kind)
                    return
                }

                null -> {
                    fail("no card was presented, so nothing was proven")
                    return
                }
            }

        // Let the validation services discover the certificate status and
        // hold the flow to the matching outcome.
        val sources =
            DebugDocumentSigningSources.create(
                context = context.applicationContext,
                transferredConfigurations = listOf(TimestampAuthorityConfiguration.shipped()),
            )
        val archival =
            try {
                QualifiedPdfArchivalCompletion.complete(
                    prepared = prepared,
                    timestampSource = sources.timestamp,
                    validationSource = sources.validation,
                )
            } finally {
                sources.close()
                prepared.close()
            }
        when (archival) {
            is QualifiedPdfArchivalResult.Success -> {
                verifySignedDocument(archival.document)
            }

            is QualifiedPdfArchivalResult.Failure -> {
                verifyRevocationRefusal(archival.kind)
            }
        }
    }

    /** A validated certificate must yield a document that verifies. */
    private fun verifySignedDocument(document: SignedPdfDocument) {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val validator = DocumentValidator(BundledIssuerCertificates.load(context))
        val validation = document.useBytes(validator::validate)
        document.close()
        val completed =
            validation as? DocumentValidationResult.Completed
                ?: run {
                    fail("the signed document did not parse as a signed PDF: " + validation)
                    return
                }
        val signature =
            completed.signatures.singleOrNull()
                ?: run {
                    fail("expected exactly one signature, saw " + completed.signatures.size)
                    return
                }
        assertTrue("the byte-range digest must match", signature.digestMatches)
        assertTrue("the CMS signature must verify", signature.signatureValid)
        assertTrue("the signature must cover the whole document", signature.coversWholeDocument)
    }

    /** A refusal is correct only when it names the signer's revocation. */
    private fun verifyRevocationRefusal(kind: QualifiedPdfArchivalFailure) {
        val validation =
            kind as? QualifiedPdfArchivalFailure.Validation
                ?: run {
                    fail("signing was refused for a reason other than revocation: " + kind)
                    return
                }
        assertEquals(
            "the refusal must name the revocation",
            ValidationMaterialCollectionFailure.REVOKED,
            validation.kind,
        )
        assertEquals(
            "the revoked certificate is the document signer's",
            ValidationPathRole.DOCUMENT_SIGNER,
            validation.pathRole,
        )
    }

    /** A minimal valid PDF with a correct cross-reference table. */
    private fun minimalPdf(): ByteArray {
        val bodies =
            listOf(
                "<</Type/Catalog/Pages 2 0 R>>",
                "<</Type/Pages/Kids[3 0 R]/Count 1>>",
                "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>",
            )
        val buffer = ByteArrayOutputStream()
        buffer.write("%PDF-1.4\n".encodeToByteArray())
        val offsets = mutableListOf<Int>()
        bodies.forEachIndexed { index, body ->
            offsets.add(buffer.size())
            buffer.write(((index + 1).toString() + " 0 obj").encodeToByteArray())
            buffer.write(body.encodeToByteArray())
            buffer.write("\nendobj\n".encodeToByteArray())
        }
        val xrefPosition = buffer.size()
        val entryCount = bodies.size + 1
        buffer.write(("xref\n0 " + entryCount + "\n").encodeToByteArray())
        buffer.write("0000000000 65535 f \n".encodeToByteArray())
        offsets.forEach { offset ->
            buffer.write((offset.toString().padStart(OFFSET_WIDTH, '0') + " 00000 n \n").encodeToByteArray())
        }
        buffer.write(
            (
                "trailer<</Size " + entryCount + "/Root 1 0 R>>\nstartxref\n" +
                    xrefPosition + "\n%%EOF"
            ).encodeToByteArray(),
        )
        return buffer.toByteArray()
    }

    private companion object {
        const val TARGET_PACKAGE = "fi.refineid.android"
        const val TARGET_ACTIVITY_CLASS = "$TARGET_PACKAGE.MainActivity"
        const val LIVE_TEST_ARGUMENT = "refineidLiveNfcSigning"
        const val LIVE_TEST_ENABLED_VALUE = "true"
        const val CAN_ARGUMENT = "refineidNfcCan"
        const val PIN2_ARGUMENT = "refineidNfcPin2"
        const val CARD_RECOGNIZED_LABEL = "Card recognized"
        const val CARD_TIMEOUT_MILLISECONDS = 60_000L
        const val SIGN_TIMEOUT_SECONDS = 60L
        const val LIVE_TEST_TIMEOUT_MILLISECONDS = 180_000L
        const val SINGLE_COMPLETION = 1
        const val OFFSET_WIDTH = 10
    }
}
