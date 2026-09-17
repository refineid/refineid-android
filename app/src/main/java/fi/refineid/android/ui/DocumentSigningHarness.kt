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
import fi.refineid.android.asic.AsicContainer
import fi.refineid.android.asic.AsicDataObject
import fi.refineid.android.asic.AsicSigningCoordinator
import fi.refineid.android.asic.AsicSigningFailure
import fi.refineid.android.asic.AsicSigningResult
import fi.refineid.android.asic.PreparedAsicSignature
import fi.refineid.android.asic.PreparedAsicSignatureResult
import fi.refineid.android.asic.QualifiedAsicArchivalCompletion
import fi.refineid.android.core.CanSubmission
import fi.refineid.android.core.Pin2Submission
import fi.refineid.android.core.QualifiedCardService
import fi.refineid.android.diagnostics.AppTrace
import fi.refineid.android.document.PdfSignatureClaim
import fi.refineid.android.document.PreparedQualifiedPdfSignature
import fi.refineid.android.document.QualifiedPdfArchivalCompletion
import fi.refineid.android.document.QualifiedPdfArchivalFailure
import fi.refineid.android.document.QualifiedPdfArchivalResult
import fi.refineid.android.document.QualifiedPdfPreparationResult
import fi.refineid.android.document.QualifiedPdfSigningCoordinator
import fi.refineid.android.document.QualifiedPdfSigningFailure
import fi.refineid.android.document.SignedDocumentName
import fi.refineid.android.document.SignedPdfDocument
import fi.refineid.android.document.ValidationMaterialCollectionFailure
import fi.refineid.android.settings.TimestampAuthorityRepository
import fi.refineid.android.settings.TimestampAuthorityStoreException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.io.IOException
import java.time.Instant
import kotlin.coroutines.resume

/**
 * How a signing request reaches the card. A wired reader already holds
 * an open session, so signing runs at once; a contactless card is not
 * assumed present, so [begin] waits for the holder to tap and hands
 * control back once the transient session is open. The access number is
 * supplied only when no card has been primed.
 */
internal class DocumentSignTap(
    val begin: (canBytes: ByteArray?, onReady: () -> Unit, onNoCard: () -> Unit) -> Unit,
    val end: () -> Unit,
    val canRequired: Boolean,
)

/** Debug-only PAdES-B-LTA file-picker harness. */
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
            ActivityResultContracts.CreateDocument(AsicContainer.MIME_TYPE),
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
    val mimeType: String,
    val isPdf: Boolean,
)

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
    private var signingSetupJob: Job? = null
    private var pendingArchivalSources: DebugDocumentSigningSources? = null
    private var archivalJob: Job? = null
    private var signedDocument: SignedPdfDocument? = null
    private var signedBatchPdfs: List<Pair<String, SignedPdfDocument>>? = null
    private var signedContainer: ByteArray? = null

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

    var saveRequest by mutableStateOf<DocumentSaveRequest?>(null)
        private set

    var saveFolderRequest by mutableStateOf(false)
        private set

    fun select(sources: List<Uri>) {
        if (isClosed || isWorking() || sources.isEmpty()) {
            return
        }
        AppTrace.documentInputStarted()
        status = DocumentSigningStatus.READING
        scope.launch {
            try {
                val items = withContext(Dispatchers.IO) { resolveItems(sources) }
                if (!isClosed) {
                    selectedItems = items
                    discardSigned()
                    status = DocumentSigningStatus.IDLE
                    AppTrace.documentInputCompleted(
                        isAccepted = true,
                        documentLength = null,
                    )
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: IOException) {
                failInput()
            } catch (_: SecurityException) {
                failInput()
            } catch (_: RuntimeException) {
                failInput()
            }
        }
    }

    fun add(sources: List<Uri>) {
        if (isClosed || isWorking() || sources.isEmpty()) {
            return
        }
        AppTrace.documentInputStarted()
        status = DocumentSigningStatus.READING
        scope.launch {
            try {
                val newSources = sources.filter { uri -> selectedItems.none { it.uri == uri } }
                val newItems = withContext(Dispatchers.IO) { resolveItems(newSources) }
                if (!isClosed) {
                    selectedItems = selectedItems + newItems
                    discardSigned()
                    status = DocumentSigningStatus.IDLE
                    AppTrace.documentInputCompleted(
                        isAccepted = true,
                        documentLength = null,
                    )
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: IOException) {
                failInput()
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
            val isPdf = name.endsWith(".pdf", ignoreCase = true) || mimeType == PDF_MEDIA_TYPE
            SelectedItem(uri = uri, name = name, mimeType = mimeType, isPdf = isPdf)
        }

    private fun readBytes(source: Uri): ByteArray =
        contentResolver.openInputStream(source)?.use { it.readBytes() }
            ?: throw IOException("file cannot be opened")

    /**
     * Commit the chosen document. Signing needs a currently ready card;
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
            status = DocumentSigningStatus.UNAVAILABLE
            return
        }
        withOpenCard(pin2, can) { granted ->
            when (targetFormat) {
                SignatureFormat.PDF -> preparePdf(service, granted)
                SignatureFormat.CONTAINER -> prepareContainer(service, granted)
            }
        }
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
        val canBytes =
            can?.transfer() ?: fi.refineid.android.core.CanSessionStore
                .canBytes()
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
            {
                pin2.close()
                if (!isClosed) {
                    status = DocumentSigningStatus.NO_CARD
                }
            },
        )
    }

    private fun prepareContainer(
        service: QualifiedCardService,
        pin2: Pin2Submission,
    ) {
        val items = selectedItems
        if (isClosed || items.isEmpty()) {
            pin2.close()
            tap()?.end?.invoke()
            return
        }
        val asicCoordinator = AsicSigningCoordinator(service)
        status = DocumentSigningStatus.SIGNING
        val running =
            scope.launch {
                try {
                    val objects =
                        withContext(Dispatchers.IO) {
                            items.map { item ->
                                AsicDataObject(
                                    name = item.name,
                                    content = readBytes(item.uri),
                                    mimeType = item.mimeType,
                                )
                            }
                        }
                    val sources =
                        withContext(Dispatchers.IO) {
                            DebugDocumentSigningSources.create(
                                context = context,
                                transferredConfigurations = timestampAuthorityRepository.load(),
                            )
                        }
                    var sourcesTransferred = false
                    try {
                        pendingArchivalSources = sources
                        val prepResult =
                            suspendCancellableCoroutine { cont ->
                                asicCoordinator.prepare(objects, pin2) { res ->
                                    cont.resume(res)
                                }
                            }
                        when (prepResult) {
                            is PreparedAsicSignatureResult.Failure -> {
                                tap()?.end?.invoke()
                                if (pendingArchivalSources === sources) {
                                    pendingArchivalSources = null
                                }
                                sources.close()
                                status = prepResult.reason.status()
                            }

                            is PreparedAsicSignatureResult.Success -> {
                                tap()?.end?.invoke()
                                if (pendingArchivalSources === sources) {
                                    pendingArchivalSources = null
                                }
                                sourcesTransferred = true
                                status = DocumentSigningStatus.FINALIZING
                                completeContainerArchival(prepResult.prepared, sources)
                            }
                        }
                    } finally {
                        if (!sourcesTransferred) {
                            pendingArchivalSources = null
                            sources.close()
                        }
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: TimestampAuthorityStoreException) {
                    tap()?.end?.invoke()
                    if (!isClosed) {
                        status = DocumentSigningStatus.UNAVAILABLE
                    }
                } catch (_: Exception) {
                    pin2.close()
                    tap()?.end?.invoke()
                    if (!isClosed) {
                        status = DocumentSigningStatus.ERROR
                    }
                }
            }
        signingSetupJob = running
    }

    private fun completeContainerArchival(
        prepared: PreparedAsicSignature,
        archivalSources: DebugDocumentSigningSources,
    ) {
        val running =
            scope.launch(start = CoroutineStart.UNDISPATCHED) {
                try {
                    val result =
                        runInterruptible(Dispatchers.IO) {
                            QualifiedAsicArchivalCompletion.complete(
                                prepared = prepared,
                                timestampSource = archivalSources.timestamp,
                                validationSource = archivalSources.validation,
                            )
                        }
                    when (result) {
                        is AsicSigningResult.Failure -> {
                            status = result.reason.status()
                        }

                        is AsicSigningResult.Success -> {
                            discardSigned()
                            signedContainer = result.container
                            saveRequest = DocumentSaveRequest(suggestedName = containerName(), isContainer = true)
                        }
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: RuntimeException) {
                    if (!isClosed) {
                        status = DocumentSigningStatus.ERROR
                    }
                } finally {
                    archivalSources.close()
                }
            }
        archivalJob = running
    }

    private fun containerName(): String {
        val items = selectedItems
        val original =
            if (items.size == 1) {
                items[0].name
            } else {
                context.getString(R.string.default_container_name)
            }
        val phrase =
            context.getString(
                R.string.signed_at,
                SignedDocumentName.instantStamp(Instant.now()),
            )
        return SignedDocumentName.suggested(
            originalName = original,
            signedAtPhrase = phrase,
            extensionOverride = AsicContainer.FILE_EXTENSION,
        )
    }

    private fun preparePdf(
        service: QualifiedCardService,
        pin2: Pin2Submission,
    ) {
        val items = selectedItems
        if (isClosed || items.isEmpty()) {
            pin2.close()
            tap()?.end?.invoke()
            return
        }
        val coordinator = QualifiedPdfSigningCoordinator(service)
        status = DocumentSigningStatus.SIGNING
        val total = items.size
        val pinBytes = pin2.consume { it.copyOf() }
        val running =
            scope.launch {
                var loadedPdfs: List<SelectedPdfDocument>? = null
                try {
                    val pdfs =
                        withContext(Dispatchers.IO) {
                            items.map { item ->
                                SelectedPdfDocument.read(contentResolver, item.uri)
                            }
                        }
                    loadedPdfs = pdfs
                    val sources =
                        withContext(Dispatchers.IO) {
                            DebugDocumentSigningSources.create(
                                context = context,
                                transferredConfigurations = timestampAuthorityRepository.load(),
                            )
                        }
                    var sourcesTransferred = false
                    try {
                        pendingArchivalSources = sources
                        val preparedList = mutableListOf<Pair<String, PreparedQualifiedPdfSignature>>()
                        var preparationFailed = false

                        for ((index, input) in pdfs.withIndex()) {
                            if (total > 1) {
                                progressText = context.getString(R.string.signing_progress, index + 1, total)
                            }
                            val docPin =
                                Pin2Submission.from(
                                    String(pinBytes.map { it.toInt().toChar() }.toCharArray()),
                                )
                            val prepResult =
                                suspendCancellableCoroutine { cont ->
                                    input.useBytes { bytes ->
                                        coordinator.prepare(
                                            document = bytes,
                                            claim =
                                                PdfSignatureClaim(
                                                    signedAt = Instant.now(),
                                                    reason = null,
                                                    location = null,
                                                ),
                                            pin2 = docPin,
                                            onResult = { res -> cont.resume(res) },
                                        )
                                    }
                                }
                            when (prepResult) {
                                is QualifiedPdfPreparationResult.Failure -> {
                                    tap()?.end?.invoke()
                                    preparationFailed = true
                                    preparedList.forEach { it.second.close() }
                                    if (pendingArchivalSources === sources) {
                                        pendingArchivalSources = null
                                    }
                                    sources.close()
                                    status = prepResult.kind.status()
                                    break
                                }

                                is QualifiedPdfPreparationResult.Success -> {
                                    preparedList.add(suggestedName(input.source) to prepResult.prepared)
                                }
                            }
                        }

                        if (!preparationFailed) {
                            tap()?.end?.invoke()
                            if (pendingArchivalSources === sources) {
                                pendingArchivalSources = null
                            }
                            sourcesTransferred = true
                            status = DocumentSigningStatus.FINALIZING
                            completeBatchArchival(preparedList, sources)
                        }
                    } finally {
                        if (!sourcesTransferred) {
                            pendingArchivalSources = null
                            sources.close()
                        }
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: TimestampAuthorityStoreException) {
                    tap()?.end?.invoke()
                    if (!isClosed) {
                        status = DocumentSigningStatus.UNAVAILABLE
                    }
                } catch (_: RuntimeException) {
                    tap()?.end?.invoke()
                    if (!isClosed) {
                        status = DocumentSigningStatus.ERROR
                    }
                } finally {
                    pinBytes.fill(0)
                    loadedPdfs?.forEach { it.close() }
                }
            }
        signingSetupJob = running
    }

    private fun completeBatchArchival(
        preparedList: List<Pair<String, PreparedQualifiedPdfSignature>>,
        archivalSources: DebugDocumentSigningSources,
    ) {
        val total = preparedList.size
        val running =
            scope.launch(start = CoroutineStart.UNDISPATCHED) {
                val completedDocs = mutableListOf<Pair<String, SignedPdfDocument>>()
                var failed = false
                try {
                    for ((index, item) in preparedList.withIndex()) {
                        val (suggestedName, prepared) = item
                        if (total > 1) {
                            progressText = context.getString(R.string.finalizing_progress, index + 1, total)
                        }
                        val result =
                            runInterruptible(Dispatchers.IO) {
                                QualifiedPdfArchivalCompletion.complete(
                                    prepared = prepared,
                                    timestampSource = archivalSources.timestamp,
                                    validationSource = archivalSources.validation,
                                )
                            }
                        when (result) {
                            is QualifiedPdfArchivalResult.Failure -> {
                                failed = true
                                status = result.kind.status()
                                break
                            }

                            is QualifiedPdfArchivalResult.Success -> {
                                completedDocs.add(suggestedName to result.document)
                            }
                        }
                    }
                    if (!failed) {
                        if (completedDocs.size == 1) {
                            val (name, doc) = completedDocs[0]
                            signedDocument = doc
                            saveRequest = DocumentSaveRequest(suggestedName = name, isContainer = false)
                        } else {
                            signedBatchPdfs = completedDocs
                            saveFolderRequest = true
                        }
                    } else {
                        completedDocs.forEach { it.second.close() }
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (interrupted: InterruptedException) {
                    throw CancellationException("archival signing was interrupted").also { cancellation ->
                        cancellation.initCause(interrupted)
                    }
                } catch (_: RuntimeException) {
                    if (!isClosed) {
                        status = DocumentSigningStatus.ERROR
                    }
                } finally {
                    archivalSources.close()
                    preparedList.forEach { it.second.close() }
                }
            }
        archivalJob = running
    }

    fun saveTo(destination: Uri?) {
        saveRequest = null
        val container = signedContainer
        val document = signedDocument
        if (destination == null || (container == null && document == null)) {
            discardSigned()
            if (!isClosed && status != DocumentSigningStatus.IDLE) {
                status = DocumentSigningStatus.IDLE
            }
            return
        }
        signedContainer = null
        signedDocument = null
        status = DocumentSigningStatus.SAVING
        scope.launch {
            val saved =
                if (container != null) {
                    val ok = saveBytes(container, destination)
                    AppTrace.documentOutputCompleted(isSuccessful = ok, documentLength = container.size)
                    ok
                } else {
                    checkNotNull(document)
                    val ok = save(document, destination)
                    AppTrace.documentOutputCompleted(isSuccessful = ok, documentLength = document.length)
                    ok
                }
            if (!isClosed) {
                if (saved) {
                    selectedItems = emptyList()
                    status = DocumentSigningStatus.SIGNED
                } else {
                    status = DocumentSigningStatus.ERROR
                }
            }
        }
    }

    fun saveAllToFolder(folderUri: Uri?) {
        saveFolderRequest = false
        val batch = signedBatchPdfs
        if (folderUri == null || batch.isNullOrEmpty()) {
            discardSigned()
            if (!isClosed && status != DocumentSigningStatus.IDLE) {
                status = DocumentSigningStatus.IDLE
            }
            return
        }
        signedBatchPdfs = null
        status = DocumentSigningStatus.SAVING
        scope.launch {
            var allSaved = true
            val total = batch.size
            try {
                withContext(Dispatchers.IO) {
                    val parentUri =
                        DocumentsContract.buildDocumentUriUsingTree(
                            folderUri,
                            DocumentsContract.getTreeDocumentId(folderUri),
                        )
                    for ((index, item) in batch.withIndex()) {
                        val (name, signedDoc) = item
                        progressText = context.getString(R.string.saving_progress, index + 1, total)
                        val newFileUri =
                            DocumentsContract.createDocument(
                                contentResolver,
                                parentUri,
                                PDF_MEDIA_TYPE,
                                name,
                            )
                        if (newFileUri != null) {
                            save(signedDoc, newFileUri)
                        } else {
                            allSaved = false
                        }
                    }
                }
            } catch (_: IOException) {
                allSaved = false
            } catch (_: SecurityException) {
                allSaved = false
            } catch (_: RuntimeException) {
                allSaved = false
            } finally {
                batch.forEach { it.second.close() }
            }
            if (!isClosed) {
                if (allSaved) {
                    selectedItems = emptyList()
                    status = DocumentSigningStatus.SIGNED
                } else {
                    status = DocumentSigningStatus.ERROR
                }
            }
        }
    }

    private suspend fun saveBytes(
        bytes: ByteArray,
        output: Uri,
    ): Boolean =
        try {
            withContext(Dispatchers.IO) {
                contentResolver.openOutputStream(output, WRITE_MODE)?.use { stream ->
                    stream.write(bytes)
                    stream.flush()
                } ?: throw IOException("container destination cannot be opened")
            }
            true
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: IOException) {
            false
        } catch (_: SecurityException) {
            false
        } catch (_: RuntimeException) {
            false
        }

    override fun close() {
        if (isClosed) {
            return
        }
        isClosed = true
        selectedItems = emptyList()
        signingSetupJob?.cancel()
        pendingArchivalSources?.close()
        pendingArchivalSources = null
        archivalJob?.cancel()
        discardSigned()
    }

    private suspend fun save(
        document: SignedPdfDocument,
        output: Uri,
    ): Boolean =
        try {
            withContext(Dispatchers.IO) {
                contentResolver.openOutputStream(output, WRITE_MODE)?.use { stream ->
                    document.useBytes(stream::write)
                    stream.flush()
                } ?: throw IOException("signed PDF destination cannot be opened")
            }
            true
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: IOException) {
            false
        } catch (_: SecurityException) {
            false
        } catch (_: RuntimeException) {
            false
        } finally {
            document.close()
        }

    private fun suggestedName(source: Uri): String {
        val original = displayName(source)
        val phrase =
            context.getString(
                R.string.signed_at,
                SignedDocumentName.instantStamp(Instant.now()),
            )
        return SignedDocumentName.suggested(originalName = original, signedAtPhrase = phrase)
    }

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
            status = DocumentSigningStatus.ERROR
            AppTrace.documentInputCompleted(isAccepted = false, documentLength = null)
        }
    }

    private fun discardSigned() {
        saveRequest = null
        saveFolderRequest = false
        signedDocument?.close()
        signedDocument = null
        signedBatchPdfs?.forEach { it.second.close() }
        signedBatchPdfs = null
        signedContainer = null
        progressText = null
    }

    private fun isWorking(): Boolean =
        status == DocumentSigningStatus.READING ||
            status == DocumentSigningStatus.HOLD_CARD ||
            status == DocumentSigningStatus.SIGNING ||
            status == DocumentSigningStatus.FINALIZING ||
            status == DocumentSigningStatus.SAVING

    private fun QualifiedPdfPreparationResult.closePreparedSignature() {
        if (this is QualifiedPdfPreparationResult.Success) {
            prepared.close()
        }
    }

    private fun QualifiedPdfArchivalResult.closeDocument() {
        if (this is QualifiedPdfArchivalResult.Success) {
            document.close()
        }
    }

    private fun QualifiedPdfArchivalFailure.status(): DocumentSigningStatus =
        when (this) {
            is QualifiedPdfArchivalFailure.Timestamp,
            QualifiedPdfArchivalFailure.ValidationUnavailable,
            -> {
                DocumentSigningStatus.UNAVAILABLE
            }

            // The card produced a valid signature; only the long-term
            // validation refused, because the certificate is revoked. That
            // is a certificate fact, not a signing fault, so it reads apart
            // from a generic error.
            is QualifiedPdfArchivalFailure.Validation -> {
                if (kind == ValidationMaterialCollectionFailure.REVOKED) {
                    DocumentSigningStatus.CERT_REVOKED
                } else {
                    DocumentSigningStatus.ERROR
                }
            }

            is QualifiedPdfArchivalFailure.Cms,
            is QualifiedPdfArchivalFailure.Document,
            QualifiedPdfArchivalFailure.InternalError,
            -> {
                DocumentSigningStatus.ERROR
            }
        }

    private fun QualifiedPdfSigningFailure.status(): DocumentSigningStatus =
        when (this) {
            is QualifiedPdfSigningFailure.Card -> {
                when (kind) {
                    fi.refineid.android.core.QualifiedSignFailure.WRONG_PIN -> {
                        DocumentSigningStatus.WRONG_PIN
                    }

                    fi.refineid.android.core.QualifiedSignFailure.PIN_LOCKED -> {
                        DocumentSigningStatus.PIN_LOCKED
                    }

                    fi.refineid.android.core.QualifiedSignFailure.CARD_UNAVAILABLE,
                    fi.refineid.android.core.QualifiedSignFailure.TRANSPORT_ERROR,
                    fi.refineid.android.core.QualifiedSignFailure.SAFETY_REFUSED,
                    -> {
                        DocumentSigningStatus.UNAVAILABLE
                    }

                    fi.refineid.android.core.QualifiedSignFailure.INVALID_PIN,
                    fi.refineid.android.core.QualifiedSignFailure.VERIFICATION_REJECTED,
                    fi.refineid.android.core.QualifiedSignFailure.CERTIFICATE_REJECTED,
                    fi.refineid.android.core.QualifiedSignFailure.INVALID_CERTIFICATE,
                    fi.refineid.android.core.QualifiedSignFailure.CERTIFICATE_MISMATCH,
                    fi.refineid.android.core.QualifiedSignFailure.KEY_PROFILE_MISMATCH,
                    fi.refineid.android.core.QualifiedSignFailure.SIGNING_REJECTED,
                    fi.refineid.android.core.QualifiedSignFailure.LOCAL_VERIFICATION_FAILED,
                    fi.refineid.android.core.QualifiedSignFailure.BRIDGE_ERROR,
                    -> {
                        DocumentSigningStatus.ERROR
                    }
                }
            }

            is QualifiedPdfSigningFailure.Certificate,
            QualifiedPdfSigningFailure.KeyProfileUnsupported,
            -> {
                DocumentSigningStatus.UNAVAILABLE
            }

            is QualifiedPdfSigningFailure.Cms,
            is QualifiedPdfSigningFailure.Document,
            QualifiedPdfSigningFailure.InternalError,
            -> {
                DocumentSigningStatus.ERROR
            }
        }

    private fun AsicSigningFailure.status(): DocumentSigningStatus =
        when (this) {
            AsicSigningFailure.KeyProfileUnsupported,
            is AsicSigningFailure.Certificate,
            AsicSigningFailure.ValidationUnavailable,
            -> DocumentSigningStatus.UNAVAILABLE

            AsicSigningFailure.UnusableNames,
            AsicSigningFailure.ContainerOverflow,
            AsicSigningFailure.Timestamp,
            is AsicSigningFailure.Validation,
            -> DocumentSigningStatus.ERROR

            is AsicSigningFailure.Card -> kind.status()
        }

    private fun fi.refineid.android.core.QualifiedSignFailure.status(): DocumentSigningStatus =
        when (this) {
            fi.refineid.android.core.QualifiedSignFailure.WRONG_PIN -> DocumentSigningStatus.WRONG_PIN

            fi.refineid.android.core.QualifiedSignFailure.PIN_LOCKED -> DocumentSigningStatus.PIN_LOCKED

            fi.refineid.android.core.QualifiedSignFailure.CARD_UNAVAILABLE,
            fi.refineid.android.core.QualifiedSignFailure.TRANSPORT_ERROR,
            fi.refineid.android.core.QualifiedSignFailure.SAFETY_REFUSED,
            -> DocumentSigningStatus.UNAVAILABLE

            fi.refineid.android.core.QualifiedSignFailure.INVALID_PIN,
            fi.refineid.android.core.QualifiedSignFailure.VERIFICATION_REJECTED,
            fi.refineid.android.core.QualifiedSignFailure.CERTIFICATE_REJECTED,
            fi.refineid.android.core.QualifiedSignFailure.INVALID_CERTIFICATE,
            fi.refineid.android.core.QualifiedSignFailure.CERTIFICATE_MISMATCH,
            fi.refineid.android.core.QualifiedSignFailure.KEY_PROFILE_MISMATCH,
            fi.refineid.android.core.QualifiedSignFailure.SIGNING_REJECTED,
            fi.refineid.android.core.QualifiedSignFailure.LOCAL_VERIFICATION_FAILED,
            fi.refineid.android.core.QualifiedSignFailure.BRIDGE_ERROR,
            -> DocumentSigningStatus.ERROR
        }

    private companion object {
        const val WRITE_MODE = "w"
        const val DEFAULT_DOCUMENT_NAME = "document.pdf"
    }
}

private const val PDF_MEDIA_TYPE = "application/pdf"
private const val ANY_MEDIA_TYPE = "*/*"
