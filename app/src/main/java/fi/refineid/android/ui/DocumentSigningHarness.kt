@file:Suppress("TooManyFunctions")

package fi.refineid.android.ui

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import fi.refineid.android.R
import fi.refineid.android.core.CanSessionStore
import fi.refineid.android.core.CanSubmission
import fi.refineid.android.core.Pin2Submission
import fi.refineid.android.core.QualifiedCardService
import fi.refineid.android.diagnostics.AppTrace
import fi.refineid.android.docsign.CardDigestSigner
import fi.refineid.android.docsign.CoreDocuments
import fi.refineid.android.docsign.NamedInput
import fi.refineid.android.docsign.Pin2Entry
import fi.refineid.android.docsign.SigningEvents
import fi.refineid.android.nfc.SignTapFailure
import fi.refineid.android.settings.TimestampAuthorityConfiguration
import fi.refineid.android.settings.TimestampAuthorityRepository
import fi.refineid.android.settings.TimestampAuthorityStoreException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.refineid_doc_sign_android.CardSignRefusal
import uniffi.refineid_doc_sign_android.DocumentFormat
import uniffi.refineid_doc_sign_android.DocumentOutcome
import uniffi.refineid_doc_sign_android.SignFailure
import uniffi.refineid_doc_sign_android.TimestampAuthority
import java.io.File
import java.io.IOException
import java.nio.file.Files

/**
 * How a signing request reaches the card. A wired reader already holds
 * an open session, so signing runs at once; a contactless card is not
 * assumed present, so [begin] waits for the holder to tap and hands
 * control back once the transient session is open. The access number is
 * supplied only when no card has been primed.
 */
internal class DocumentSignTap(
    val begin: (canBytes: ByteArray?, onReady: () -> Unit, onFailure: (SignTapFailure) -> Unit) -> Unit,
    val end: () -> Unit,
    val canRequired: Boolean,
)

/**
 * The Sign screen: choose files, sign them with the card through the
 * core (each PDF as PAdES, or every file as one ASiC-E container), and
 * save what the core wrote where the holder picks.
 */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun DocumentSigningHarness(
    signingAvailable: Boolean,
    cardService: QualifiedCardService?,
    tap: DocumentSignTap?,
    timestampAuthorityRepository: TimestampAuthorityRepository?,
    onComplete: () -> Unit = {},
) {
    if (timestampAuthorityRepository == null) {
        return
    }
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    // The session, its scope, and every picker registration below live
    // for the whole signing visit. Card readiness, the chosen service,
    // and the tap are deliberately not session keys: a transient
    // CHECKING state must neither discard a document already chosen
    // nor reroute the signing, so the session reads them through
    // holders at sign time and only the sign action is gated.
    val tapHolder =
        remember {
            object {
                var value: DocumentSignTap? = null
            }
        }
    tapHolder.value = tap
    val serviceHolder =
        remember {
            object {
                var value: QualifiedCardService? = null
            }
        }
    serviceHolder.value = cardService
    val availabilityHolder =
        remember {
            object {
                var value = true
            }
        }
    availabilityHolder.value = signingAvailable
    val session =
        remember(context.contentResolver, scope, timestampAuthorityRepository) {
            DocumentSigningHarnessSession(
                context = context.applicationContext,
                contentResolver = context.contentResolver,
                cardService = { serviceHolder.value },
                isAvailable = { availabilityHolder.value },
                scope = scope,
                timestampAuthorityRepository = timestampAuthorityRepository,
                tap = { tapHolder.value },
            )
        }
    DisposableEffect(session) {
        onDispose(session::close)
    }
    val chooseFilesLauncher =
        rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { sources ->
            if (sources.isNotEmpty()) {
                session.select(sources)
            }
        }
    val addFilesLauncher =
        rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { sources ->
            if (sources.isNotEmpty()) {
                session.add(sources)
            }
        }
    val pdfDestinationPicker =
        rememberLauncherForActivityResult(
            ActivityResultContracts.CreateDocument(PDF_MEDIA_TYPE),
        ) { destination ->
            session.saveTo(destination)
        }
    val containerDestinationPicker =
        rememberLauncherForActivityResult(
            ActivityResultContracts.CreateDocument(ASIC_E_MEDIA_TYPE),
        ) { destination ->
            session.saveTo(destination)
        }
    val folderDestinationPicker =
        rememberLauncherForActivityResult(
            ActivityResultContracts.OpenDocumentTree(),
        ) { folderUri ->
            session.saveAllToFolder(folderUri)
        }
    // Signing chooses the destination only once there is a signed file to
    // save, so the save panel opens with the suggested name after the tap.
    LaunchedEffect(session.saveRequest) {
        session.saveRequest?.let { request ->
            if (request.isContainer) {
                containerDestinationPicker.launch(request.suggestedName)
            } else {
                pdfDestinationPicker.launch(request.suggestedName)
            }
        }
    }
    LaunchedEffect(session.saveFolderRequest) {
        if (session.saveFolderRequest) {
            folderDestinationPicker.launch(null)
        }
    }
    LaunchedEffect(session.status) {
        if (session.status == DocumentSigningStatus.SIGNED) {
            onComplete()
        }
    }

    DocumentSigningCard(
        hasDocument = session.hasDocument,
        documentNames = session.documentNames,
        canSignPdf = session.canSignPdf,
        progressText = session.progressText,
        canRequired = tap?.canRequired == true,
        canSign = signingAvailable,
        status = session.status,
        failure = session.failure,
        belowLongTerm = session.belowLongTerm,
        onChooseDocuments = { chooseFilesLauncher.launch(arrayOf(ANY_MEDIA_TYPE)) },
        onAddDocument = { addFilesLauncher.launch(arrayOf(ANY_MEDIA_TYPE)) },
        onSign = session::sign,
    )
}

/** A signed file waiting for the holder to choose where it lands. */
internal data class DocumentSaveRequest(
    val suggestedName: String,
    val isContainer: Boolean = false,
)

private data class SelectedItem(
    val uri: Uri,
    val name: String,
    val isPdf: Boolean,
)

/**
 * What the core wrote and where it waits in [directory] until saved:
 * the signed files, whether they are one container, and the status the
 * signing ends with once they are saved ([DocumentSigningStatus.SIGNED]
 * unless some document's finish failed).
 */
private class SignedOutputs(
    val directory: File,
    val files: List<File>,
    val isContainer: Boolean,
    val savedStatus: DocumentSigningStatus,
) {
    fun discard() {
        directory.deleteRecursively()
    }
}

@Suppress("LargeClass")
internal class DocumentSigningHarnessSession(
    private val context: Context,
    private val contentResolver: ContentResolver,
    private val cardService: () -> QualifiedCardService?,
    private val isAvailable: () -> Boolean,
    private val scope: CoroutineScope,
    private val timestampAuthorityRepository: TimestampAuthorityRepository,
    private val tap: () -> DocumentSignTap?,
) : AutoCloseable {
    private var selectedItems by mutableStateOf<List<SelectedItem>>(emptyList())
    private var isClosed = false
    private var signingJob: Job? = null
    private var signed: SignedOutputs? = null

    val documentNames: List<String>
        get() = selectedItems.map { it.name }

    val canSignPdf: Boolean
        get() = selectedItems.isNotEmpty() && selectedItems.all { it.isPdf }

    val hasDocument: Boolean
        get() = selectedItems.isNotEmpty()

    var progressText by mutableStateOf<String?>(null)
        private set

    var status by mutableStateOf(DocumentSigningStatus.IDLE)
        private set

    /** Why signing stopped; read while [status] is [DocumentSigningStatus.FAILED]. */
    var failure by mutableStateOf<DocumentSigningFailure?>(null)
        private set

    /** What the saved development document lacks; read while [status] is SIGNED_BELOW_LONG_TERM. */
    var belowLongTerm by mutableStateOf<BelowLongTermNotice?>(null)
        private set

    var saveRequest by mutableStateOf<DocumentSaveRequest?>(null)
        private set

    var saveFolderRequest by mutableStateOf(false)
        private set

    private val documentsDirectory: File
        get() = File(context.cacheDir, DOCUMENTS_DIRECTORY)

    fun select(sources: List<Uri>) {
        choose(sources) { items -> items }
    }

    fun add(sources: List<Uri>) {
        choose(sources.filter { uri -> selectedItems.none { it.uri == uri } }) { items -> selectedItems + items }
    }

    private fun choose(
        sources: List<Uri>,
        merge: (List<SelectedItem>) -> List<SelectedItem>,
    ) {
        if (isClosed || isWorking()) {
            return
        }
        AppTrace.documentInputStarted()
        status = DocumentSigningStatus.READING
        scope.launch {
            try {
                val items = withContext(Dispatchers.IO) { resolveItems(sources) }
                if (!isClosed) {
                    selectedItems = merge(items)
                    discardSigned()
                    status = DocumentSigningStatus.IDLE
                    AppTrace.documentInputCompleted(
                        isAccepted = true,
                        documentLength = null,
                    )
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: SecurityException) {
                failInput()
            } catch (_: RuntimeException) {
                failInput()
            }
        }
    }

    private fun resolveItems(sources: List<Uri>): List<SelectedItem> =
        sources.map { uri ->
            val name = displayName(uri)
            val mimeType = contentResolver.getType(uri) ?: ANY_MEDIA_TYPE
            val isPdf = name.endsWith(PDF_EXTENSION, ignoreCase = true) || mimeType == PDF_MEDIA_TYPE
            SelectedItem(uri = uri, name = name, isPdf = isPdf)
        }

    /**
     * Commit the chosen documents. Signing needs a currently ready card;
     * without one the request is refused visibly and the submission is
     * discarded. A wired session signs at once; a contactless card first
     * waits for the tap behind a hold prompt.
     */
    fun sign(
        targetFormat: SignatureFormat,
        pin2: Pin2Submission,
        can: CanSubmission?,
    ) {
        if (isClosed || isWorking() || !hasDocument) {
            pin2.close()
            can?.close()
            return
        }
        val service = cardService()
        if (!isAvailable() || service == null) {
            pin2.close()
            can?.close()
            fail(CardNotReadyFailure)
            return
        }
        withOpenCard(pin2, can) { granted -> runSigning(service, granted, targetFormat) }
    }

    private fun withOpenCard(
        pin2: Pin2Submission,
        can: CanSubmission?,
        run: (Pin2Submission) -> Unit,
    ) {
        val activeTap = tap()
        if (activeTap == null) {
            can?.close()
            run(pin2)
            return
        }
        val canBytes = can?.transfer() ?: CanSessionStore.canBytes()
        status = DocumentSigningStatus.HOLD_CARD
        activeTap.begin(
            canBytes,
            {
                if (!isClosed) {
                    run(pin2)
                } else {
                    pin2.close()
                }
            },
            { failure ->
                pin2.close()
                if (!isClosed) {
                    status = failure.signingStatus()
                }
            },
        )
    }

    /** Sign the chosen documents with the card through the core, then ask where to save. */
    private fun runSigning(
        service: QualifiedCardService,
        pin2: Pin2Submission,
        targetFormat: SignatureFormat,
    ) {
        val items = selectedItems
        if (isClosed || items.isEmpty()) {
            pin2.close()
            tap()?.end?.invoke()
            return
        }
        status = DocumentSigningStatus.SIGNING
        val entry = SingleEntry(pin2)
        val events = HolderEvents()
        signingJob =
            scope.launch {
                try {
                    val outputs =
                        withContext(Dispatchers.IO) { signOnCard(service, items, targetFormat, entry, events) }
                    offerSave(outputs)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: SignFailure) {
                    AppTrace.documentSigningFailed(failureName(failure))
                    finish(signingStatusOf(failure, entry.wrongPin))
                } catch (_: TimestampAuthorityStoreException) {
                    AppTrace.documentSigningFailed(TIMESTAMP_SETTINGS_FAILURE)
                    finish(DocumentSigningStatus.UNAVAILABLE)
                } catch (failure: IOException) {
                    AppTrace.documentSigningFailed(failure.javaClass.simpleName)
                    finish(DocumentSigningStatus.ERROR)
                } catch (_: RuntimeException) {
                    AppTrace.documentSigningFailed(RUNTIME_FAILURE)
                    finish(DocumentSigningStatus.ERROR)
                } finally {
                    entry.close()
                    tap()?.end?.invoke()
                }
            }
    }

    /** The holder's events from the signing thread, shown on the main thread. */
    private inner class HolderEvents : SigningEvents {
        override fun signing(
            index: Int,
            total: Int,
        ) {
            if (total > 1) {
                scope.launch {
                    progressText = context.getString(R.string.signing_progress, index + 1, total)
                }
            }
        }

        override fun signed() {
            scope.launch {
                tap()?.end?.invoke()
                progressText = null
                if (status == DocumentSigningStatus.SIGNING) {
                    status = DocumentSigningStatus.FINALIZING
                }
            }
        }
    }

    /** The core's signing of [items] into a fresh output directory; blocks on the card and the network. */
    private fun signOnCard(
        service: QualifiedCardService,
        items: List<SelectedItem>,
        targetFormat: SignatureFormat,
        entry: Pin2Entry,
        events: SigningEvents,
    ): SignedOutputs {
        CoreDocuments.installHttpClient()
        documentsDirectory.mkdirs()
        val outputDirectory = Files.createTempDirectory(documentsDirectory.toPath(), OUTPUT_PREFIX).toFile()
        val authorities = timestampAuthorities()
        var kept = false
        try {
            val format =
                when (targetFormat) {
                    SignatureFormat.PDF -> DocumentFormat.PADES
                    SignatureFormat.CONTAINER -> DocumentFormat.ASIC_E
                }
            val outcomes =
                CardDigestSigner(service, entry, events).use { signer ->
                    CoreDocuments.sign(
                        signer = signer,
                        inputs = items.map { item -> NamedInput(item.name) { openInput(item.uri) } },
                        workDirectory = documentsDirectory,
                        outputDirectory = outputDirectory,
                        format = format,
                        locale = context.resources.configuration.locales[0],
                        timestampAuthorities = authorities,
                    )
                }
            val files = outcomes.filterIsInstance<DocumentOutcome.Signed>().map { File(it.document.path) }
            val failure = outcomes.filterIsInstance<DocumentOutcome.Failed>().firstOrNull()?.failure
            if (files.isEmpty()) {
                throw failure ?: SignFailure.OutputWrite()
            }
            failure?.let { AppTrace.documentSigningFailed(failureName(it)) }
            return SignedOutputs(
                directory = outputDirectory,
                files = files,
                isContainer = format == DocumentFormat.ASIC_E,
                savedStatus = failure?.let { signingStatusOf(it, wrongPin = false) } ?: DocumentSigningStatus.SIGNED,
            ).also { kept = true }
        } finally {
            if (!kept) {
                outputDirectory.deleteRecursively()
            }
            authorities.forEach { authority -> authority.login?.password?.fill(CLEARED_BYTE) }
        }
    }

    /** The holder's configured authorities as the core takes them; the shipped one when none is stored. */
    private fun timestampAuthorities(): List<TimestampAuthority> {
        val configurations = timestampAuthorityRepository.load()
        return try {
            configurations.map(TimestampAuthorityConfiguration::coreAuthority)
        } finally {
            configurations.forEach(TimestampAuthorityConfiguration::close)
        }
    }

    private fun offerSave(outputs: SignedOutputs) {
        if (isClosed) {
            outputs.discard()
            return
        }
        discardSigned()
        signed = outputs
        if (outputs.files.size == 1) {
            saveRequest =
                DocumentSaveRequest(suggestedName = outputs.files.single().name, isContainer = outputs.isContainer)
        } else {
            saveFolderRequest = true
        }
    }

    fun saveTo(destination: Uri?) {
        saveRequest = null
        val outputs = signed
        if (destination == null || outputs == null || outputs.files.size != 1) {
            discardSigned()
            if (!isClosed && status != DocumentSigningStatus.IDLE) {
                status = DocumentSigningStatus.IDLE
            }
            return
        }
        signed = null
        status = DocumentSigningStatus.SAVING
        scope.launch {
            val file = outputs.files.single()
            val length = file.length()
            val saved = withContext(Dispatchers.IO) { deliver(file, destination) }
            outputs.discard()
            AppTrace.documentOutputCompleted(isSuccessful = saved, documentLength = length.toInt())
            finishSaving(saved, outputs.savedStatus)
        }
    }

    fun saveAllToFolder(folderUri: Uri?) {
        saveFolderRequest = false
        val outputs = signed
        if (folderUri == null || outputs == null || outputs.files.size < 2) {
            discardSigned()
            if (!isClosed && status != DocumentSigningStatus.IDLE) {
                status = DocumentSigningStatus.IDLE
            }
            return
        }
        signed = null
        status = DocumentSigningStatus.SAVING
        scope.launch {
            val total = outputs.files.size
            val saved =
                withContext(Dispatchers.IO) {
                    try {
                        val parentUri =
                            DocumentsContract.buildDocumentUriUsingTree(
                                folderUri,
                                DocumentsContract.getTreeDocumentId(folderUri),
                            )
                        outputs.files.withIndex().all { (index, file) ->
                            withContext(Dispatchers.Main) {
                                progressText = context.getString(R.string.saving_progress, index + 1, total)
                            }
                            val created =
                                DocumentsContract.createDocument(contentResolver, parentUri, PDF_MEDIA_TYPE, file.name)
                            created != null && deliver(file, created)
                        }
                    } catch (_: IOException) {
                        false
                    } catch (_: SecurityException) {
                        false
                    } catch (_: RuntimeException) {
                        false
                    }
                }
            outputs.discard()
            finishSaving(saved, outputs.savedStatus)
        }
    }

    /** Copy [file] to [destination]; false when the destination refuses it. */
    private fun deliver(
        file: File,
        destination: Uri,
    ): Boolean =
        try {
            CoreDocuments.deliver(file.absolutePath) {
                contentResolver.openOutputStream(destination, WRITE_MODE)
                    ?: throw IOException("signed document destination cannot be opened")
            }
            true
        } catch (_: IOException) {
            false
        } catch (_: SecurityException) {
            false
        } catch (_: RuntimeException) {
            false
        }

    private fun finishSaving(
        saved: Boolean,
        savedStatus: DocumentSigningStatus,
    ) {
        if (isClosed) {
            return
        }
        progressText = null
        if (saved) {
            selectedItems = emptyList()
            status = savedStatus
        } else {
            status = DocumentSigningStatus.ERROR
        }
    }

    private fun finish(failed: DocumentSigningStatus) {
        if (!isClosed) {
            progressText = null
            status = failed
        }
    }

    override fun close() {
        if (isClosed) {
            return
        }
        isClosed = true
        selectedItems = emptyList()
        signingJob?.cancel()
        discardSigned()
    }

    private fun openInput(source: Uri) =
        contentResolver.openInputStream(source) ?: throw IOException("chosen document cannot be opened")

    private fun displayName(source: Uri): String {
        val projection = arrayOf(OpenableColumns.DISPLAY_NAME)
        val name =
            try {
                contentResolver.query(source, projection, null, null, null)?.use { cursor ->
                    if (cursor.moveToFirst()) {
                        val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                        if (index >= 0) cursor.getString(index) else null
                    } else {
                        null
                    }
                }
            } catch (_: RuntimeException) {
                null
            }
        return name?.takeIf { it.isNotBlank() } ?: DEFAULT_DOCUMENT_NAME
    }

    private fun failInput() {
        if (!isClosed) {
            fail(FileUnreadableFailure)
            AppTrace.documentInputCompleted(isAccepted = false, documentLength = null)
        }
    }

    private fun fail(cause: DocumentSigningFailure) {
        if (!isClosed) {
            failure = cause
            status = DocumentSigningStatus.FAILED
        }
    }

    private fun discardSigned() {
        saveRequest = null
        saveFolderRequest = false
        signed?.discard()
        signed = null
        progressText = null
    }

    private fun isWorking(): Boolean =
        status == DocumentSigningStatus.READING ||
            status == DocumentSigningStatus.HOLD_CARD ||
            status == DocumentSigningStatus.SIGNING ||
            status == DocumentSigningStatus.FINALIZING ||
            status == DocumentSigningStatus.SAVING

    /**
     * The PIN 2 the holder entered on the card before signing, given once.
     * A wrong PIN ends the signing so the holder enters it again on the
     * card, as before any signature; [wrongPin] records that it happened.
     */
    private class SingleEntry(
        first: Pin2Submission,
    ) : Pin2Entry,
        AutoCloseable {
        private var pending: Pin2Submission? = first
        private var given = false

        @Volatile
        var wrongPin = false
            private set

        override fun pin2(attemptsLeft: Int?): Pin2Submission? {
            if (given) {
                wrongPin = true
                return null
            }
            given = true
            return pending.also { pending = null }
        }

        override fun close() {
            pending?.close()
            pending = null
        }
    }

    private companion object {
        const val WRITE_MODE = "w"
        const val DEFAULT_DOCUMENT_NAME = "document.pdf"
        const val PDF_EXTENSION = ".pdf"
        const val DOCUMENTS_DIRECTORY = "documents"
        const val OUTPUT_PREFIX = "signed-"
        const val TIMESTAMP_SETTINGS_FAILURE = "TimestampAuthorityStoreException"
        const val RUNTIME_FAILURE = "RuntimeException"
        const val CLEARED_BYTE: Byte = 0

        /** The failure's type and case, never the core's account of it. */
        fun failureName(failure: SignFailure): String =
            when (failure) {
                is SignFailure.Card -> {
                    failure.javaClass.simpleName + NAME_SEPARATOR +
                        failure.refusal.javaClass.simpleName
                }

                else -> {
                    failure.javaClass.simpleName
                }
            }

        const val NAME_SEPARATOR = "."
    }
}

/** What the signing screen says when a contactless card did not serve the signature. */
internal fun SignTapFailure.signingStatus(): DocumentSigningStatus =
    when (this) {
        SignTapFailure.NO_CARD -> DocumentSigningStatus.NO_CARD
        SignTapFailure.CARD_LEFT -> DocumentSigningStatus.CARD_LEFT
        SignTapFailure.ACCESS_NUMBER_REQUIRED -> DocumentSigningStatus.ACCESS_NUMBER_REQUIRED
        SignTapFailure.ORGANIZATION_CARD_NOT_READ -> DocumentSigningStatus.ORGANIZATION_CARD_NOT_READ
        SignTapFailure.NO_KNOWN_KIND -> DocumentSigningStatus.CARD_NO_KNOWN_KIND
        SignTapFailure.ACCESS_FILE_REFUSED -> DocumentSigningStatus.CARD_ACCESS_FILE_REFUSED
        SignTapFailure.ACCESS_FILE_MALFORMED -> DocumentSigningStatus.CARD_ACCESS_FILE_MALFORMED
        SignTapFailure.READ_FAILED -> DocumentSigningStatus.CARD_READ_FAILED
    }

private const val PDF_MEDIA_TYPE = "application/pdf"
private const val ASIC_E_MEDIA_TYPE = "application/vnd.etsi.asic-e+zip"
private const val ANY_MEDIA_TYPE = "*/*"

/** The status a refused signing ends in; a declined re-entry after a wrong PIN reads as the wrong PIN. */
internal fun signingStatusOf(
    failure: SignFailure,
    wrongPin: Boolean,
): DocumentSigningStatus =
    when (failure) {
        is SignFailure.Card -> {
            when (failure.refusal) {
                is CardSignRefusal.Declined -> {
                    if (wrongPin) DocumentSigningStatus.WRONG_PIN else DocumentSigningStatus.ERROR
                }

                is CardSignRefusal.RetryFloor -> {
                    DocumentSigningStatus.PIN_LOCKED
                }

                is CardSignRefusal.CardUnavailable,
                is CardSignRefusal.Expired,
                is CardSignRefusal.Unsupported,
                -> {
                    DocumentSigningStatus.UNAVAILABLE
                }

                is CardSignRefusal.CardFailed -> {
                    DocumentSigningStatus.ERROR
                }
            }
        }

        is SignFailure.Revoked -> {
            DocumentSigningStatus.CERT_REVOKED
        }

        is SignFailure.Certificate,
        is SignFailure.Timestamp,
        is SignFailure.Material,
        -> {
            DocumentSigningStatus.UNAVAILABLE
        }

        is SignFailure.Document,
        is SignFailure.InputRead,
        is SignFailure.OutputWrite,
        is SignFailure.SignatureInvalid,
        -> {
            DocumentSigningStatus.ERROR
        }
    }
