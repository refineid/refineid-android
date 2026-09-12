@file:Suppress("LongMethod", "MagicNumber", "MaxLineLength", "UnusedParameter")

package fi.refineid.android.ui

import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.InputTransformation
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.TextObfuscationMode
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.KeyboardArrowRight
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Create
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SecureTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.PathParser
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import fi.refineid.android.BuildConfig
import fi.refineid.android.R
import fi.refineid.android.core.AuthenticationCardService
import fi.refineid.android.core.AuthenticationPinCache
import fi.refineid.android.core.CanSessionStore
import fi.refineid.android.core.CanSubmission
import fi.refineid.android.core.PersonCardDetails
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.core.QualifiedCardService
import fi.refineid.android.diagnostics.AppTrace
import fi.refineid.android.diagnostics.BuildDiagnostics
import fi.refineid.android.diagnostics.DiagnosticsCollector
import fi.refineid.android.nfc.NfcReaderSnapshot
import fi.refineid.android.nfc.NfcReaderStatus
import fi.refineid.android.rapp.RappAuthorizationInbox
import fi.refineid.android.rapp.RappPairingModel
import fi.refineid.android.settings.TimestampAuthorityRepository
import fi.refineid.android.usb.CardPresence
import fi.refineid.android.usb.ReaderConnectionStatus
import fi.refineid.android.usb.UsbReaderSnapshot
import kotlinx.coroutines.delay

/** The screens the grouped home navigates to, one at a time. */
private enum class MainDestination {
    HOME,
    VERIFY,
    SIGN,
    PAIRING,
    PERSON,
    CARD_MANAGEMENT,
    DIAGNOSTICS,
}

@Suppress("CyclomaticComplexMethod", "FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun MainScreen(
    snapshot: UsbReaderSnapshot,
    onRequestPermission: () -> Unit,
    onSelectUsbDevice: (Int) -> Unit = {},
    onReaderConnect: (CanSubmission, ((ByteArray?) -> Unit)?) -> Unit = { _, _ -> },
    browserCardService: AuthenticationCardService? = null,
    qualifiedCardService: QualifiedCardService? = null,
    nfcQualifiedCardService: QualifiedCardService? = null,
    cardManagementService: fi.refineid.android.core.CardManagementService? = null,
    nfcCardManagementService: fi.refineid.android.core.CardManagementService? = null,
    timestampAuthorityRepository: TimestampAuthorityRepository? = null,
    hasNfc: Boolean = true,
    nfcSnapshot: NfcReaderSnapshot = NfcReaderSnapshot(),
    onOpenNfcSettings: () -> Unit = {},
    onNfcConnect: (CanSubmission?, Pin1Submission?) -> Unit = { _, _ -> },
    onForgetPrimedCard: () -> Unit = {},
    nfcCardService: AuthenticationCardService? = null,
    onSignBeginTap: (ByteArray?, () -> Unit, () -> Unit) -> Unit = { _, _, _ -> },
    onSignEndTap: () -> Unit = {},
    pinCache: AuthenticationPinCache? = null,
    rappPairingModel: RappPairingModel? = null,
    rappInbox: RappAuthorizationInbox? = null,
    remoteCardModel: fi.refineid.android.rapp.RemoteCardModel? = null,
    onPin1Changed: () -> Unit = {},
    onReadPhoto: (((ByteArray?) -> Unit) -> Unit)? = null,
) {
    var showsPhotoReadNfcDialog by remember { mutableStateOf(false) }
    var pendingPhotoConsumer by remember { mutableStateOf<((ByteArray?) -> Unit)?>(null) }

    LaunchedEffect(nfcSnapshot.status, pendingPhotoConsumer) {
        val nfcReady =
            nfcSnapshot.status == NfcReaderStatus.CARD_READY ||
                nfcSnapshot.status == NfcReaderStatus.ACTIVATION_REQUIRED
        if (nfcReady && pendingPhotoConsumer != null && fi.refineid.android.core.CanSessionStore.hasCan) {
            val consumer = pendingPhotoConsumer
            pendingPhotoConsumer = null
            showsPhotoReadNfcDialog = false
            onReadPhoto?.invoke { bytes ->
                consumer?.invoke(bytes)
            }
        }
    }

    var userDismissedUsbCanDialog by rememberSaveable { mutableStateOf(false) }
    var isSubmittingUsbCan by remember { mutableStateOf(false) }

    LaunchedEffect(snapshot.cardPresence) {
        if (snapshot.cardPresence != CardPresence.PRESENT) {
            userDismissedUsbCanDialog = false
        }
    }

    LaunchedEffect(snapshot.status) {
        if (snapshot.status != ReaderConnectionStatus.CHECKING) {
            isSubmittingUsbCan = false
        }
    }

    val usbCardAwaitsCan =
        snapshot.cardPresence == CardPresence.PRESENT &&
            !CanSessionStore.hasCan &&
            (
                snapshot.status == ReaderConnectionStatus.ACCESS_NUMBER_REQUIRED ||
                    snapshot.status == ReaderConnectionStatus.WRONG_ACCESS_NUMBER
            )

    val showsUsbCanDialog =
        !userDismissedUsbCanDialog &&
            snapshot.cardPresence == CardPresence.PRESENT &&
            (usbCardAwaitsCan || (isSubmittingUsbCan && snapshot.status == ReaderConnectionStatus.CHECKING))

    val fallbackRemoteName = remember { kotlinx.coroutines.flow.MutableStateFlow<String?>(null) }
    val fallbackRemoteDetails = remember { kotlinx.coroutines.flow.MutableStateFlow<PersonCardDetails?>(null) }
    val remoteHolderName by (remoteCardModel?.holderName ?: fallbackRemoteName).collectAsState()
    val remoteDetails by (remoteCardModel?.cardDetails ?: fallbackRemoteDetails).collectAsState()

    LaunchedEffect(Unit) {
        remoteCardModel?.refresh()
    }

    val usbCardReady =
        snapshot.status == ReaderConnectionStatus.READY &&
            snapshot.cardPresence == CardPresence.PRESENT
    val usbReaderPresent = snapshot.status != ReaderConnectionStatus.NOT_CONNECTED

    val usbActivationRequired = snapshot.status == ReaderConnectionStatus.ACTIVATION_REQUIRED
    val nfcActivationRequired = nfcSnapshot.status == NfcReaderStatus.ACTIVATION_REQUIRED
    val isActivationRequired = usbActivationRequired || nfcActivationRequired
    val isMultipleUnactivated = usbActivationRequired && nfcActivationRequired

    val unactivatedCardLabel =
        when {
            isMultipleUnactivated -> {
                val usbLabel = snapshot.holderName ?: stringResource(R.string.card_transport_usb)
                val nfcLabel = nfcSnapshot.holderName ?: stringResource(R.string.card_transport_nfc)
                "$usbLabel, $nfcLabel"
            }

            usbActivationRequired -> {
                snapshot.holderName
                    ?: snapshot.cardDetails?.documentNumber?.let { "Document $it" }
                    ?: stringResource(R.string.card_transport_usb)
            }

            nfcActivationRequired -> {
                nfcSnapshot.holderName
                    ?: nfcSnapshot.cardDetails?.documentNumber?.let { "Document $it" }
                    ?: stringResource(R.string.card_transport_nfc)
            }

            else -> {
                null
            }
        }

    var destination by rememberSaveable { mutableStateOf(MainDestination.HOME) }
    var activePersonDetails by remember { mutableStateOf<PersonCardDetails?>(null) }

    // Signing follows the one-transport rule: a wired reader signs on
    // its open session, while a contactless card is never assumed
    // present — the holder taps it when prompted.
    val nfcSigningAvailable =
        !usbReaderPresent &&
            nfcSnapshot.status != NfcReaderStatus.NOT_AVAILABLE &&
            nfcSnapshot.status != NfcReaderStatus.TURNED_OFF
    val remoteSigningAvailable = !hasNfc && remoteHolderName != null
    val signingAvailable =
        (usbCardReady || nfcSigningAvailable || remoteSigningAvailable) && !isActivationRequired

    rappInbox?.currentRequest?.let { req ->
        RappAuthorizationDialog(request = req)
    }

    rappInbox?.currentTapPrompt?.let { prompt ->
        RappCardTapDialog(prompt = prompt)
    }

    var validationUri by remember { mutableStateOf<Uri?>(null) }
    val verifyPicker =
        rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) {
                validationUri = uri
                destination = MainDestination.VERIFY
            }
        }

    BackHandler(enabled = destination != MainDestination.HOME) {
        rappPairingModel?.reset()
        validationUri = null
        destination = MainDestination.HOME
    }

    val effectiveHolderName =
        if (usbCardReady) {
            snapshot.holderName
        } else {
            nfcSnapshot.holderName ?: snapshot.holderName ?: remoteHolderName
        }
    val effectiveDetails =
        if (usbCardReady) {
            snapshot.cardDetails
        } else {
            nfcSnapshot.cardDetails ?: snapshot.cardDetails ?: remoteDetails
        }
    val performFullIdentityReset: () -> Unit = {
        onForgetPrimedCard()
        CanSessionStore.drop()
        pinCache?.clear()
        onPin1Changed()
        rappPairingModel?.terminate()
        remoteCardModel?.forget()
    }
    val forgetIdentity: (() -> Unit)? =
        if (usbCardReady) {
            null
        } else {
            performFullIdentityReset
        }

    val cardItems =
        buildList {
            if (snapshot.availableReaders.size > 1) {
                snapshot.availableReaders.forEach { reader ->
                    val readerTitle =
                        reader.holderName
                            ?: if (reader.cardPresence == CardPresence.PRESENT) {
                                stringResource(R.string.card_transport_usb)
                            } else {
                                reader.name
                            }
                    add(
                        CardIdentityItem(
                            id = "reader/${reader.deviceId}",
                            title = readerTitle,
                            transportLabel = reader.name,
                            isActivationRequired = reader.isActivationRequired,
                            isSelected = reader.isSelected,
                            details = if (reader.isSelected) snapshot.cardDetails else null,
                            onSelect = { onSelectUsbDevice(reader.deviceId) },
                        ),
                    )
                }
            } else if (usbCardReady || snapshot.status == ReaderConnectionStatus.ACTIVATION_REQUIRED) {
                val title = snapshot.holderName ?: stringResource(R.string.card_transport_usb)
                add(
                    CardIdentityItem(
                        id = "reader/active",
                        title = title,
                        transportLabel = stringResource(R.string.card_transport_usb),
                        isActivationRequired = snapshot.status == ReaderConnectionStatus.ACTIVATION_REQUIRED,
                        isSelected = true,
                        details = snapshot.cardDetails,
                    ),
                )
            }

            if (nfcSnapshot.holderName != null ||
                nfcSnapshot.status == NfcReaderStatus.CARD_READY ||
                nfcSnapshot.status == NfcReaderStatus.ACTIVATION_REQUIRED ||
                nfcSnapshot.isPrimed
            ) {
                val title = nfcSnapshot.holderName ?: stringResource(R.string.card_transport_nfc)
                add(
                    CardIdentityItem(
                        id = "contactless/active",
                        title = title,
                        transportLabel = stringResource(R.string.card_transport_nfc),
                        isActivationRequired = nfcSnapshot.status == NfcReaderStatus.ACTIVATION_REQUIRED,
                        isSelected = !usbCardReady,
                        details = nfcSnapshot.cardDetails,
                        onForget = forgetIdentity,
                    ),
                )
            }

            if (remoteHolderName != null) {
                add(
                    CardIdentityItem(
                        id = "remote/active",
                        title = remoteHolderName ?: stringResource(R.string.connect_id_card),
                        transportLabel = stringResource(R.string.connected_to_computer),
                        isActivationRequired = false,
                        isSelected = !usbCardReady && nfcSnapshot.holderName == null,
                        details = remoteDetails,
                        onForget = forgetIdentity,
                    ),
                )
            }
        }

    val onOpenPersonForCard: (CardIdentityItem) -> Unit = { card ->
        activePersonDetails = card.details ?: PersonCardDetails.fromHolderName(card.title)
        destination = MainDestination.PERSON
    }

    val browserAvailable =
        (usbCardReady || effectiveHolderName != null) && !isActivationRequired

    when (destination) {
        MainDestination.HOME -> {
            HomeScreen(
                signingAvailable = signingAvailable,
                browserAvailable = browserAvailable,
                holderName = effectiveHolderName,
                hasNfc = hasNfc,
                isActivationRequired = isActivationRequired,
                unactivatedCardLabel = unactivatedCardLabel,
                isMultipleUnactivated = isMultipleUnactivated,
                cards = cardItems,
                onOpenPersonForCard = onOpenPersonForCard,
                onForgetIdentity = forgetIdentity,
                onWrongPin = performFullIdentityReset,
                onOpenPerson = { destination = MainDestination.PERSON },
                onOpenDiagnostics = { destination = MainDestination.DIAGNOSTICS },
                browserCardService =
                    if (usbCardReady) {
                        browserCardService
                    } else if (hasNfc && (nfcSnapshot.isPrimed || nfcSnapshot.cardDetails != null)) {
                        nfcCardService ?: browserCardService
                    } else {
                        remoteCardModel?.authenticationCardService ?: nfcCardService ?: browserCardService
                    },
                pinCache = pinCache,
                nfcStatus =
                    if (usbCardReady || nfcSnapshot.status == NfcReaderStatus.NOT_AVAILABLE) {
                        null
                    } else {
                        nfcSnapshot.status
                    },
                nfcPrimed = nfcSnapshot.isPrimed,
                onNfcConnect = onNfcConnect,
                // A present wired card reads over its open session; the
                // contactless path primes NFC for the next tap otherwise.
                // The wired branch consumes no PIN, so the optional PIN1
                // buffer is zeroized instead of being left for GC.
                onReadCard = { can, pin1 ->
                    if (snapshot.cardPresence == CardPresence.PRESENT && can != null) {
                        pin1?.close()
                        onReaderConnect(can, null)
                    } else {
                        onNfcConnect(can, pin1)
                    }
                },
                timestampAuthorityRepository = timestampAuthorityRepository,
                onOpenVerify = { verifyPicker.launch(arrayOf("*/*")) },
                onOpenSign = { destination = MainDestination.SIGN },
                onOpenPairing = { destination = MainDestination.PAIRING },
                onOpenCardManagement = { destination = MainDestination.CARD_MANAGEMENT },
                onRequestUsbCan =
                    if (usbCardAwaitsCan) {
                        { userDismissedUsbCanDialog = false }
                    } else {
                        null
                    },
            )
        }

        MainDestination.VERIFY -> {
            SubScreen(
                title = stringResource(R.string.verify),
                tag = UiAutomationIds.VERIFY_SCREEN,
                onBack = {
                    validationUri = null
                    destination = MainDestination.HOME
                },
            ) {
                DocumentValidationHarness(initialUri = validationUri)
            }
        }

        MainDestination.SIGN -> {
            SubScreen(
                title = stringResource(R.string.sign),
                tag = UiAutomationIds.SIGN_SCREEN,
                onBack = { destination = MainDestination.HOME },
            ) {
                DocumentSigningHarness(
                    signingAvailable = signingAvailable,
                    cardService =
                        if (usbCardReady) {
                            qualifiedCardService
                        } else {
                            nfcQualifiedCardService
                        },
                    tap =
                        if (usbCardReady) {
                            null
                        } else {
                            DocumentSignTap(
                                begin = onSignBeginTap,
                                end = onSignEndTap,
                                canRequired = !nfcSnapshot.isPrimed,
                            )
                        },
                    timestampAuthorityRepository = timestampAuthorityRepository,
                    onComplete = { destination = MainDestination.HOME },
                )
            }
        }

        MainDestination.PAIRING -> {
            SubScreen(
                title = stringResource(R.string.pair_computer),
                tag = "RappPairingScreen",
                onBack = {
                    rappPairingModel?.reset()
                    destination = MainDestination.HOME
                },
            ) {
                rappPairingModel?.let { model ->
                    RappPairingScreen(
                        model = model,
                        hasNfc = hasNfc,
                        pinCache = pinCache,
                        holderName = effectiveHolderName,
                        onConnectCard = { can, pin1 ->
                            onNfcConnect(can, pin1)
                        },
                        onBack = {
                            model.reset()
                            destination = MainDestination.HOME
                        },
                    )
                }
            }
        }

        MainDestination.PERSON -> {
            val details =
                activePersonDetails
                    ?: effectiveDetails
                    ?: PersonCardDetails.fromHolderName(effectiveHolderName ?: "")
            SubScreen(
                title = stringResource(R.string.section_identity),
                tag = "PersonScreen",
                onBack = {
                    activePersonDetails = null
                    destination = MainDestination.HOME
                },
            ) {
                PersonScreen(
                    details = details,
                    activationRequired = isActivationRequired,
                    onActivate = { destination = MainDestination.CARD_MANAGEMENT },
                    onReadPhoto = { onLoaded ->
                        if (fi.refineid.android.core.CanSessionStore.hasCan) {
                            onReadPhoto?.invoke(onLoaded)
                        } else {
                            pendingPhotoConsumer = onLoaded
                            showsPhotoReadNfcDialog = true
                        }
                    },
                )
            }
        }

        MainDestination.CARD_MANAGEMENT -> {
            var detectedNeedsActivation by remember { mutableStateOf(false) }
            val effectiveActivationRequired = isActivationRequired || detectedNeedsActivation
            SubScreen(
                title =
                    stringResource(
                        if (effectiveActivationRequired) R.string.card_activation else R.string.card_pins,
                    ),
                tag = "CardManagementScreen",
                onBack = { destination = MainDestination.HOME },
            ) {
                CardManagementScreen(
                    cardManagementService =
                        if (usbCardReady || snapshot.status == ReaderConnectionStatus.ACTIVATION_REQUIRED) {
                            cardManagementService
                        } else {
                            nfcCardManagementService
                        },
                    onConnectNfc = { can ->
                        onNfcConnect(can, null)
                    },
                    isCardReady =
                        usbCardReady || nfcSnapshot.status == NfcReaderStatus.CARD_READY || isActivationRequired,
                    activationRequired = effectiveActivationRequired,
                    pinCache = pinCache,
                    onPin1Changed = onPin1Changed,
                    onActivationSucceeded = {
                        detectedNeedsActivation = false
                        destination = MainDestination.HOME
                    },
                    onNeedsActivationChanged = { needs ->
                        detectedNeedsActivation = needs
                    },
                )
            }
        }

        MainDestination.DIAGNOSTICS -> {
            var refreshKey by remember { mutableIntStateOf(0) }
            val context = LocalContext.current
            val diagSnapshot =
                remember(refreshKey, nfcSnapshot, snapshot, effectiveHolderName, effectiveDetails) {
                    DiagnosticsCollector.collect(
                        context = context,
                        nfcReaderStatus = nfcSnapshot.status,
                        usbReaderStatus = snapshot.status,
                        holderName = effectiveHolderName,
                        cardDetails = effectiveDetails,
                    )
                }
            SubScreen(
                title = stringResource(R.string.diagnostics),
                tag = UiAutomationIds.DIAGNOSTICS_SCREEN,
                onBack = { destination = MainDestination.HOME },
            ) {
                DiagnosticsScreen(
                    snapshot = diagSnapshot,
                    onRefresh = { refreshKey++ },
                    onClearLogs = { AppTrace.clearTraceLog() },
                )
            }
        }
    }

    if (showsUsbCanDialog) {
        ReaderCanDialog(
            status = snapshot.status,
            onDismiss = {
                userDismissedUsbCanDialog = true
            },
            onConnect = { can ->
                isSubmittingUsbCan = true
                onReaderConnect(can, null)
            },
        )
    }

    if (showsPhotoReadNfcDialog) {
        ReadCardNfcDialog(
            onDismiss = {
                showsPhotoReadNfcDialog = false
                pendingPhotoConsumer?.invoke(null)
                pendingPhotoConsumer = null
            },
            onConnect = { can, _ ->
                val canDigits = can?.peekDigits()
                if (canDigits != null) {
                    fi.refineid.android.core.CanSessionStore
                        .remember(canDigits)
                }
                val consumer = pendingPhotoConsumer
                pendingPhotoConsumer = null
                showsPhotoReadNfcDialog = false
                if (can != null) {
                    if (snapshot.cardPresence == CardPresence.PRESENT) {
                        onReaderConnect(can) { bytes ->
                            consumer?.invoke(bytes)
                        }
                    } else {
                        onNfcConnect(can, null)
                        if (consumer != null) {
                            pendingPhotoConsumer = consumer
                        }
                    }
                }
            },
            canOnly = true,
            isActivationRequired = isActivationRequired,
        )
    }
}

/**
 * The reference home: terse grouped navigation — the Document rows
 * first, then the card, then the browser — every workflow on its own
 * pushed screen.
 */
@Suppress("FunctionName", "ktlint:standard:function-naming", "LongParameterList")
@Composable
private fun HomeScreen(
    signingAvailable: Boolean,
    browserAvailable: Boolean = false,
    holderName: String?,
    hasNfc: Boolean = true,
    isActivationRequired: Boolean = false,
    unactivatedCardLabel: String? = null,
    isMultipleUnactivated: Boolean = false,
    cards: List<CardIdentityItem> = emptyList(),
    onOpenPersonForCard: ((CardIdentityItem) -> Unit)? = null,
    onForgetIdentity: (() -> Unit)?,
    onWrongPin: (() -> Unit)? = null,
    onOpenPerson: () -> Unit,
    onOpenDiagnostics: () -> Unit = {},
    browserCardService: AuthenticationCardService?,
    pinCache: AuthenticationPinCache?,
    nfcStatus: NfcReaderStatus?,
    nfcPrimed: Boolean,
    onNfcConnect: (CanSubmission?, Pin1Submission?) -> Unit,
    onReadCard: (CanSubmission?, Pin1Submission?) -> Unit,
    timestampAuthorityRepository: TimestampAuthorityRepository?,
    onOpenVerify: () -> Unit,
    onOpenSign: () -> Unit,
    onOpenPairing: () -> Unit,
    onOpenCardManagement: () -> Unit,
    onRequestUsbCan: (() -> Unit)? = null,
) {
    Scaffold(
        modifier =
            Modifier
                .semantics { testTagsAsResourceId = true }
                .testTag(UiAutomationIds.MAIN_SCREEN),
        bottomBar = {
            if (BuildDiagnostics.DIAGNOSTICS_VIEW_ENABLED) {
                DiagnosticsFooter(
                    onOpenDiagnostics = onOpenDiagnostics,
                )
            }
        },
    ) { contentPadding ->
        Column(
            modifier =
                Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(contentPadding)
                    .padding(
                        horizontal = SCREEN_HORIZONTAL_PADDING,
                        vertical = SCREEN_VERTICAL_PADDING,
                    ),
            verticalArrangement = Arrangement.spacedBy(SCREEN_ITEM_SPACING),
        ) {
            if (isActivationRequired) {
                ActivationBanner(
                    cardLabel = unactivatedCardLabel,
                    isMultiple = isMultipleUnactivated,
                    onActivate = onOpenCardManagement,
                )
            }

            Section(stringResource(R.string.section_document)) {
                NavigationGroup {
                    NavigationRow(
                        icon = Icons.Outlined.CheckCircle,
                        label = stringResource(R.string.verify),
                        tag = UiAutomationIds.VERIFY_ROW,
                        onClick = onOpenVerify,
                    )
                    if (!isActivationRequired) {
                        HorizontalDivider(modifier = Modifier.padding(start = GROUP_DIVIDER_INSET))
                        NavigationRow(
                            icon = Icons.Outlined.Create,
                            label = stringResource(R.string.sign),
                            tag = UiAutomationIds.SIGN_ROW,
                            enabled = signingAvailable,
                            onClick = onOpenSign,
                        )
                    }
                }
            }

            if (!isActivationRequired) {
                Section(stringResource(R.string.card)) {
                    NavigationGroup {
                        BrowserHarness(
                            cardService = browserCardService,
                            pinCache = pinCache,
                            nfcStatus = nfcStatus,
                            nfcPrimed = nfcPrimed,
                            enabled = browserAvailable,
                            onNfcConnect = { can, pin1 -> onNfcConnect(can, pin1) },
                            onWrongPin = onWrongPin,
                            launcher = { onOpen ->
                                NavigationRow(
                                    icon = painterResource(R.drawable.ic_globe),
                                    label = stringResource(R.string.browser),
                                    tag = UiAutomationIds.BROWSER_ACTION,
                                    enabled = browserAvailable,
                                    onClick = onOpen,
                                )
                            },
                        )
                        HorizontalDivider(modifier = Modifier.padding(start = GROUP_DIVIDER_INSET))
                        NavigationRow(
                            icon = painterResource(R.drawable.ic_satellite_alt),
                            label = stringResource(R.string.pair_computer),
                            tag = "RappPairingRow",
                            onClick = onOpenPairing,
                        )
                        HorizontalDivider(modifier = Modifier.padding(start = GROUP_DIVIDER_INSET))
                        NavigationRow(
                            icon = Icons.Outlined.Lock,
                            label = stringResource(R.string.card_pins),
                            tag = "manageCard",
                            onClick = onOpenCardManagement,
                        )
                    }
                }
            }

            IdentitySection(
                holderName = holderName,
                hasNfc = hasNfc,
                isActivationRequired = isActivationRequired,
                onForget = onForgetIdentity,
                onOpenPerson = onOpenPerson,
                onReadCard = onReadCard,
                onOpenPairing = onOpenPairing,
                pinCache = pinCache,
                cards = cards,
                onOpenPersonForCard = onOpenPersonForCard,
                onRequestUsbCan = onRequestUsbCan,
            )

            if (BuildDiagnostics.TIMESTAMP_SETTINGS_ENABLED) {
                TimestampSettingsRow(timestampAuthorityRepository)
            }
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun DiagnosticsFooter(onOpenDiagnostics: () -> Unit) {
    Surface(
        modifier =
            Modifier
                .fillMaxWidth()
                .clickable(onClick = onOpenDiagnostics)
                .testTag(UiAutomationIds.DIAGNOSTICS_BUTTON),
        color = MaterialTheme.colorScheme.surface,
        tonalElevation = 2.dp,
    ) {
        Row(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .navigationBarsPadding()
                    .padding(vertical = 12.dp, horizontal = 16.dp),
            horizontalArrangement = Arrangement.Center,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                painter = painterResource(R.drawable.ic_android),
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(18.dp),
            )
            Spacer(modifier = Modifier.width(8.dp))
            val diagnosticsLabel = stringResource(R.string.diagnostics)
            Text(
                text = "$diagnosticsLabel - ${BuildConfig.VERSION_NAME} (${BuildConfig.BUILD_NUMBER})",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming", "LongParameterList")
@Composable
private fun IdentitySection(
    holderName: String?,
    hasNfc: Boolean = true,
    isActivationRequired: Boolean = false,
    onForget: (() -> Unit)?,
    onOpenPerson: () -> Unit,
    onReadCard: (CanSubmission?, Pin1Submission?) -> Unit,
    onOpenPairing: () -> Unit = {},
    pinCache: AuthenticationPinCache? = null,
    cards: List<CardIdentityItem> = emptyList(),
    onOpenPersonForCard: ((CardIdentityItem) -> Unit)? = null,
    onRequestUsbCan: (() -> Unit)? = null,
) {
    var showsForgetConfirmation by remember { mutableStateOf(false) }
    var showsNfcReadDialog by remember { mutableStateOf(false) }

    Section(stringResource(R.string.section_identity)) {
        NavigationGroup {
            if (cards.size > 1) {
                cards.forEachIndexed { index, card ->
                    if (index > 0) {
                        HorizontalDivider(modifier = Modifier.padding(start = GROUP_DIVIDER_INSET))
                    }
                    CardItemRow(
                        card = card,
                        onClick = {
                            card.onSelect?.invoke()
                            if (card.isSelected && onRequestUsbCan != null && card.details == null) {
                                onRequestUsbCan()
                            } else if (card.details != null || card.title.isNotEmpty()) {
                                onOpenPersonForCard?.invoke(card) ?: onOpenPerson()
                            }
                        },
                    )
                }
            } else {
                Row(
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .clickable {
                                val personPageComplete = holderName != null
                                if (personPageComplete) {
                                    onOpenPerson()
                                } else if (onRequestUsbCan != null) {
                                    onRequestUsbCan()
                                } else if (!hasNfc) {
                                    onOpenPairing()
                                } else {
                                    showsNfcReadDialog = true
                                }
                            }.padding(horizontal = ROW_HORIZONTAL_PADDING, vertical = ROW_VERTICAL_PADDING)
                            .testTag(UiAutomationIds.IDENTITY_ROW),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(ROW_ITEM_SPACING),
                ) {
                    Icon(
                        imageVector = Icons.Outlined.Person,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(ROW_ICON_SIZE),
                    )
                    Text(
                        text =
                            holderName
                                ?: stringResource(
                                    if (onRequestUsbCan != null) {
                                        R.string.access_number_required
                                    } else if (hasNfc) {
                                        R.string.read_identity_card
                                    } else {
                                        R.string.connect_id_card
                                    },
                                ),
                        style = MaterialTheme.typography.bodyLarge,
                        color =
                            if (holderName != null) {
                                MaterialTheme.colorScheme.onSurface
                            } else {
                                MaterialTheme.colorScheme.onSurfaceVariant
                            },
                        modifier = Modifier.weight(ROW_LABEL_WEIGHT),
                    )
                    if ((holderName != null || pinCache?.hasPin == true) && onForget != null) {
                        IconButton(
                            onClick = { showsForgetConfirmation = true },
                            modifier =
                                Modifier
                                    .size(44.dp)
                                    .testTag("forgetCardIdentityButton"),
                        ) {
                            Icon(
                                imageVector = MinusCircleIcon,
                                contentDescription = stringResource(R.string.forget_identity),
                                tint = MaterialTheme.colorScheme.error,
                                modifier = Modifier.size(24.dp),
                            )
                        }
                    } else {
                        Icon(
                            imageVector = Icons.AutoMirrored.Outlined.KeyboardArrowRight,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(20.dp),
                        )
                    }
                }
            }
        }
    }

    if (showsForgetConfirmation && onForget != null) {
        AlertDialog(
            onDismissRequest = { showsForgetConfirmation = false },
            title = {
                Text(
                    text = stringResource(R.string.forget_identity_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        showsForgetConfirmation = false
                        onForget()
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
                ) {
                    Text(stringResource(R.string.forget))
                }
            },
            dismissButton = {
                OutlinedButton(onClick = { showsForgetConfirmation = false }) {
                    Text(stringResource(R.string.cancel))
                }
            },
        )
    }

    if (showsNfcReadDialog) {
        ReadCardNfcDialog(
            onDismiss = { showsNfcReadDialog = false },
            onConnect = { can, pin1 ->
                onReadCard(can, pin1)
            },
            isActivationRequired = isActivationRequired,
        )
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun ReadCardNfcDialog(
    onDismiss: () -> Unit,
    onConnect: (CanSubmission?, Pin1Submission?) -> Unit,
    canOnly: Boolean = false,
    isActivationRequired: Boolean = false,
) {
    val initialCan = remember { fi.refineid.android.core.CanSessionStore.currentCan ?: "" }
    val canState = remember { TextFieldState(initialCan) }
    val pinState = remember { TextFieldState() }

    var remainingCooldown by remember {
        mutableIntStateOf(
            fi.refineid.android.core.CanSessionStore
                .remainingCooldownSeconds(canState.text),
        )
    }
    LaunchedEffect(canState.text) {
        while (true) {
            remainingCooldown =
                fi.refineid.android.core.CanSessionStore
                    .remainingCooldownSeconds(canState.text)
            if (remainingCooldown <= 0) break
            delay(1000L)
        }
    }

    val isCanBlocked = remainingCooldown > 0
    val canReady = CanSubmission.isComplete(canState.text) && !isCanBlocked

    val submit = {
        if (canReady) {
            fi.refineid.android.core.CanSessionStore
                .remember(canState.text)
            val can = CanSubmission.from(canState.text)
            val pin1 =
                if (!canOnly && !isActivationRequired && Pin1Submission.isComplete(pinState.text)) {
                    Pin1Submission.from(pinState.text)
                } else {
                    null
                }
            onConnect(can, pin1)
            onDismiss()
        }
        Unit
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = stringResource(R.string.read_identity_card),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.SemiBold,
            )
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                SecureTextField(
                    state = canState,
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .testTag(UiAutomationIds.NFC_CAN_FIELD),
                    label = { Text(stringResource(R.string.can)) },
                    inputTransformation = CanInputTransformation,
                    textObfuscationMode = TextObfuscationMode.Visible,
                    keyboardOptions =
                        KeyboardOptions(
                            autoCorrectEnabled = false,
                            keyboardType = KeyboardType.NumberPassword,
                            imeAction = if (canOnly || isActivationRequired) ImeAction.Done else ImeAction.Next,
                        ),
                    isError = isCanBlocked,
                    supportingText = {
                        if (isCanBlocked) {
                            Text(
                                text = stringResource(R.string.can_rejected_cooldown, remainingCooldown),
                                color = MaterialTheme.colorScheme.error,
                            )
                        }
                    },
                    onKeyboardAction = {
                        if (canOnly || isActivationRequired) {
                            submit()
                        }
                    },
                )
                if (!canOnly && !isActivationRequired) {
                    SecureTextField(
                        state = pinState,
                        modifier =
                            Modifier
                                .fillMaxWidth()
                                .testTag(UiAutomationIds.NFC_PIN1_FIELD),
                        label = { Text(stringResource(R.string.pin1_optional)) },
                        inputTransformation = Pin1InputTransformation,
                        textObfuscationMode = TextObfuscationMode.Hidden,
                        keyboardOptions =
                            KeyboardOptions(
                                autoCorrectEnabled = false,
                                keyboardType = KeyboardType.NumberPassword,
                                imeAction = ImeAction.Done,
                            ),
                        onKeyboardAction = { submit() },
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = submit,
                enabled = canReady,
            ) {
                Text(stringResource(R.string.read_identity_card))
            }
        },
        dismissButton = {
            OutlinedButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel))
            }
        },
    )
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun ReaderCanDialog(
    status: ReaderConnectionStatus,
    onDismiss: () -> Unit,
    onConnect: (CanSubmission) -> Unit,
) {
    val initialCan = remember { CanSessionStore.currentCan ?: "" }
    val canState = remember { TextFieldState(initialCan) }

    var remainingCooldown by remember {
        mutableIntStateOf(
            CanSessionStore.remainingCooldownSeconds(canState.text),
        )
    }
    LaunchedEffect(canState.text) {
        while (true) {
            remainingCooldown =
                CanSessionStore.remainingCooldownSeconds(canState.text)
            if (remainingCooldown <= 0) break
            delay(1000L)
        }
    }

    val isCanBlocked = remainingCooldown > 0
    val isChecking = status == ReaderConnectionStatus.CHECKING
    val rejectedCan = CanSessionStore.mostRecentRejectedCan
    val isRejectedCanCurrent = rejectedCan != null && canState.text.contentEquals(rejectedCan)
    val isWrongCan = status == ReaderConnectionStatus.WRONG_ACCESS_NUMBER && isRejectedCanCurrent
    val canReady = CanSubmission.isComplete(canState.text) && !isCanBlocked && !isChecking

    val submit = {
        if (canReady) {
            CanSessionStore.remember(canState.text)
            val can = CanSubmission.from(canState.text)
            onConnect(can)
        }
    }

    AlertDialog(
        modifier = Modifier.testTag(UiAutomationIds.READER_CAN_DIALOG),
        onDismissRequest = {
            if (!isChecking) {
                onDismiss()
            }
        },
        title = {
            Text(
                text =
                    stringResource(
                        if (status == ReaderConnectionStatus.WRONG_ACCESS_NUMBER && isRejectedCanCurrent) {
                            R.string.wrong_can
                        } else {
                            R.string.access_number_required
                        },
                    ),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.SemiBold,
            )
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                SecureTextField(
                    state = canState,
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .testTag(UiAutomationIds.READER_CAN_FIELD),
                    label = { Text(stringResource(R.string.can)) },
                    inputTransformation = CanInputTransformation,
                    textObfuscationMode = TextObfuscationMode.Visible,
                    keyboardOptions =
                        KeyboardOptions(
                            autoCorrectEnabled = false,
                            keyboardType = KeyboardType.NumberPassword,
                            imeAction = ImeAction.Done,
                        ),
                    isError = isCanBlocked || isWrongCan,
                    supportingText = {
                        if (isCanBlocked) {
                            Text(
                                text = stringResource(R.string.can_rejected_cooldown, remainingCooldown),
                                color = MaterialTheme.colorScheme.error,
                            )
                        } else if (isWrongCan) {
                            Text(
                                text = stringResource(R.string.wrong_can),
                                color = MaterialTheme.colorScheme.error,
                            )
                        }
                    },
                    onKeyboardAction = { submit() },
                )
            }
        },
        confirmButton = {
            Button(
                onClick = submit,
                enabled = canReady,
                modifier = Modifier.testTag(UiAutomationIds.READER_CONNECT_ACTION),
            ) {
                Text(
                    stringResource(
                        if (isChecking) R.string.checking else R.string.unlock,
                    ),
                )
            }
        },
        dismissButton = {
            OutlinedButton(
                onClick = onDismiss,
                enabled = !isChecking,
                modifier = Modifier.testTag(UiAutomationIds.READER_CANCEL_ACTION),
            ) {
                Text(stringResource(R.string.cancel))
            }
        },
    )
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun TimestampSettingsRow(timestampAuthorityRepository: TimestampAuthorityRepository?) {
    TimestampAuthoritySettingsHarness(
        repository = timestampAuthorityRepository,
        launcher = { onOpen ->
            NavigationGroup {
                NavigationRow(
                    icon = Icons.Outlined.Settings,
                    label = stringResource(R.string.timestamp_authorities),
                    tag = UiAutomationIds.TIMESTAMP_SETTINGS_ACTION,
                    onClick = onOpen,
                )
            }
        },
    )
}

internal val Pin1InputTransformation =
    InputTransformation {
        if (!Pin1Submission.acceptsEntry(asCharSequence())) {
            revertAllChanges()
        }
    }

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun NfcCard(
    snapshot: NfcReaderSnapshot,
    onOpenNfcSettings: () -> Unit,
    onConnect: (CanSubmission?, Pin1Submission) -> Unit,
    onForgetPrimedCard: () -> Unit,
) {
    val statusColor =
        when (snapshot.status) {
            NfcReaderStatus.CARD_RECOGNIZED -> successStatusColor()

            NfcReaderStatus.CARD_READY -> successStatusColor()

            NfcReaderStatus.CARD_NOT_SUPPORTED -> MaterialTheme.colorScheme.error

            NfcReaderStatus.WRONG_CAN -> MaterialTheme.colorScheme.error

            NfcReaderStatus.TRANSPORT_ERROR -> MaterialTheme.colorScheme.error

            NfcReaderStatus.TURNED_OFF -> permissionStatusColor()

            NfcReaderStatus.CHECKING -> MaterialTheme.colorScheme.primary

            NfcReaderStatus.CONNECTING -> MaterialTheme.colorScheme.primary

            NfcReaderStatus.WAITING_FOR_CARD,
            NfcReaderStatus.NOT_AVAILABLE,
            NfcReaderStatus.ACTIVATION_REQUIRED,
            -> MaterialTheme.colorScheme.onSurfaceVariant
        }
    val statusTitle =
        when (snapshot.status) {
            NfcReaderStatus.WAITING_FOR_CARD -> {
                stringResource(R.string.ready)
            }

            NfcReaderStatus.CHECKING,
            NfcReaderStatus.CONNECTING,
            -> {
                stringResource(R.string.checking)
            }

            NfcReaderStatus.CARD_RECOGNIZED -> {
                stringResource(R.string.card_recognized)
            }

            NfcReaderStatus.CARD_READY -> {
                stringResource(R.string.ready)
            }

            NfcReaderStatus.WRONG_CAN -> {
                stringResource(R.string.wrong_can)
            }

            NfcReaderStatus.CARD_NOT_SUPPORTED -> {
                stringResource(R.string.card_not_supported)
            }

            NfcReaderStatus.TRANSPORT_ERROR -> {
                stringResource(R.string.error)
            }

            NfcReaderStatus.TURNED_OFF,
            NfcReaderStatus.NOT_AVAILABLE,
            NfcReaderStatus.ACTIVATION_REQUIRED,
            -> {
                stringResource(R.string.off)
            }
        }

    Card(
        modifier =
            Modifier
                .fillMaxWidth()
                .testTag(UiAutomationIds.NFC_CARD),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = CARD_ELEVATION),
        shape = RoundedCornerShape(CARD_CORNER_RADIUS),
    ) {
        Column(
            modifier = Modifier.padding(CARD_PADDING),
            verticalArrangement = Arrangement.spacedBy(CARD_ITEM_SPACING),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(READER_STATUS_ITEM_SPACING),
            ) {
                Box(
                    modifier =
                        Modifier
                            .size(READER_STATUS_INDICATOR_SIZE)
                            .background(statusColor, CircleShape),
                )
                Column {
                    Text(
                        text = stringResource(R.string.nfc),
                        fontWeight = FontWeight.SemiBold,
                        style = MaterialTheme.typography.titleLarge,
                    )
                    Text(
                        text = statusTitle,
                        color = statusColor,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }

            if (snapshot.isPrimed) {
                NfcPrimedRow(onForgetPrimedCard = onForgetPrimedCard)
            }

            // Collect the credentials needed to unlock: the access
            // number and PIN1 together, or PIN1 alone once minted.
            if (
                snapshot.status == NfcReaderStatus.CARD_RECOGNIZED ||
                snapshot.status == NfcReaderStatus.WRONG_CAN ||
                snapshot.status == NfcReaderStatus.TRANSPORT_ERROR
            ) {
                NfcCredentialEntry(isPrimed = snapshot.isPrimed, onConnect = onConnect)
            }

            if (snapshot.status == NfcReaderStatus.CARD_READY) {
                HorizontalDivider()
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = stringResource(R.string.card),
                        style = MaterialTheme.typography.bodyLarge,
                    )
                    Text(
                        text = stringResource(R.string.present),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.bodyLarge,
                    )
                }
            }

            if (snapshot.status == NfcReaderStatus.TURNED_OFF) {
                Button(
                    onClick = onOpenNfcSettings,
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .testTag(UiAutomationIds.NFC_ACTION),
                ) {
                    Text(stringResource(R.string.turn_on))
                }
            }
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun NfcPrimedRow(onForgetPrimedCard: () -> Unit) {
    HorizontalDivider()
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(READER_STATUS_ITEM_SPACING),
    ) {
        Text(
            text = stringResource(R.string.card_primed),
            color = successStatusColor(),
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.weight(WEIGHT_FILL),
        )
        Button(
            onClick = onForgetPrimedCard,
            modifier = Modifier.testTag(UiAutomationIds.NFC_FORGET_ACTION),
        ) {
            Text(stringResource(R.string.forget))
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun NfcCredentialEntry(
    isPrimed: Boolean,
    onConnect: (CanSubmission?, Pin1Submission) -> Unit,
) {
    val initialCan = remember { fi.refineid.android.core.CanSessionStore.currentCan ?: "" }
    val canState = remember { TextFieldState(initialCan) }
    val pinState = remember { TextFieldState() }
    DisposableEffect(canState, pinState) {
        onDispose {
            canState.clearText()
            pinState.clearText()
        }
    }
    val hasRememberedCan = isPrimed || fi.refineid.android.core.CanSessionStore.hasCan
    val canReady = hasRememberedCan || CanSubmission.isComplete(canState.text)
    val pinReady = Pin1Submission.isComplete(pinState.text)
    val submit = {
        if (canReady && pinReady) {
            val can =
                when {
                    isPrimed -> {
                        null
                    }

                    CanSubmission.isComplete(canState.text) -> {
                        fi.refineid.android.core.CanSessionStore
                            .remember(canState.text)
                        CanSubmission.from(canState.text)
                    }

                    fi.refineid.android.core.CanSessionStore.hasCan -> {
                        fi.refineid.android.core.CanSessionStore.currentCan
                            ?.let { CanSubmission.from(it) }
                    }

                    else -> {
                        null
                    }
                }
            val pin1 = Pin1Submission.from(pinState.text)
            pinState.clearText()
            onConnect(can, pin1)
        }
        Unit
    }

    if (!isPrimed) {
        SecureTextField(
            state = canState,
            modifier =
                Modifier
                    .fillMaxWidth()
                    .testTag(UiAutomationIds.NFC_CAN_FIELD),
            label = { Text(stringResource(R.string.can)) },
            inputTransformation = CanInputTransformation,
            textObfuscationMode = TextObfuscationMode.Visible,
            keyboardOptions =
                KeyboardOptions(
                    autoCorrectEnabled = false,
                    keyboardType = KeyboardType.NumberPassword,
                    imeAction = ImeAction.Next,
                ),
        )
    }
    SecureTextField(
        state = pinState,
        modifier =
            Modifier
                .fillMaxWidth()
                .testTag(UiAutomationIds.NFC_PIN1_FIELD),
        label = { Text(stringResource(R.string.pin1)) },
        inputTransformation = Pin1InputTransformation,
        textObfuscationMode = TextObfuscationMode.Hidden,
        keyboardOptions =
            KeyboardOptions(
                autoCorrectEnabled = false,
                keyboardType = KeyboardType.NumberPassword,
                imeAction = ImeAction.Done,
            ),
        onKeyboardAction = { submit() },
    )
    Button(
        onClick = submit,
        modifier =
            Modifier
                .fillMaxWidth()
                .testTag(UiAutomationIds.NFC_CONNECT_ACTION),
        enabled = canReady && pinReady,
    ) {
        Text(
            stringResource(
                if (isPrimed) {
                    R.string.unlock
                } else {
                    R.string.sign_in
                },
            ),
        )
    }
}

internal val CanInputTransformation =
    InputTransformation {
        if (!CanSubmission.acceptsEntry(asCharSequence())) {
            revertAllChanges()
        }
    }

@Composable
private fun readerStatusColor(status: ReaderConnectionStatus): Color =
    when (status) {
        ReaderConnectionStatus.READY -> successStatusColor()
        ReaderConnectionStatus.PERMISSION_REQUEST_FAILED -> MaterialTheme.colorScheme.error
        ReaderConnectionStatus.CARD_ERROR -> MaterialTheme.colorScheme.error
        ReaderConnectionStatus.TRANSPORT_ERROR -> MaterialTheme.colorScheme.error
        ReaderConnectionStatus.PERMISSION_REQUIRED -> permissionStatusColor()
        ReaderConnectionStatus.CHECKING -> MaterialTheme.colorScheme.primary
        ReaderConnectionStatus.NOT_CONNECTED -> MaterialTheme.colorScheme.onSurfaceVariant
        ReaderConnectionStatus.ACCESS_NUMBER_REQUIRED -> permissionStatusColor()
        ReaderConnectionStatus.WRONG_ACCESS_NUMBER -> MaterialTheme.colorScheme.error
        ReaderConnectionStatus.ACTIVATION_REQUIRED -> successStatusColor()
    }

@Composable
private fun readerStatusTitle(status: ReaderConnectionStatus): String =
    when (status) {
        ReaderConnectionStatus.READY -> {
            stringResource(R.string.ready)
        }

        ReaderConnectionStatus.PERMISSION_REQUIRED -> {
            stringResource(R.string.permission_required)
        }

        ReaderConnectionStatus.PERMISSION_REQUEST_FAILED -> {
            stringResource(R.string.access_failed)
        }

        ReaderConnectionStatus.CARD_ERROR -> {
            stringResource(R.string.error)
        }

        ReaderConnectionStatus.TRANSPORT_ERROR -> {
            stringResource(R.string.error)
        }

        ReaderConnectionStatus.CHECKING -> {
            stringResource(R.string.checking)
        }

        ReaderConnectionStatus.NOT_CONNECTED -> {
            stringResource(R.string.not_connected)
        }

        ReaderConnectionStatus.ACCESS_NUMBER_REQUIRED -> {
            stringResource(R.string.access_number_required)
        }

        ReaderConnectionStatus.WRONG_ACCESS_NUMBER -> {
            stringResource(R.string.wrong_can)
        }

        ReaderConnectionStatus.ACTIVATION_REQUIRED -> {
            stringResource(R.string.ready)
        }
    }

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun ReaderCard(
    snapshot: UsbReaderSnapshot,
    onRequestPermission: () -> Unit,
    onConnect: (CanSubmission) -> Unit,
) {
    val statusColor = readerStatusColor(snapshot.status)
    val statusTitle = readerStatusTitle(snapshot.status)

    Card(
        modifier =
            Modifier
                .fillMaxWidth()
                .testTag(UiAutomationIds.READER_CARD),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = CARD_ELEVATION),
        shape = RoundedCornerShape(CARD_CORNER_RADIUS),
    ) {
        Column(
            modifier = Modifier.padding(CARD_PADDING),
            verticalArrangement = Arrangement.spacedBy(CARD_ITEM_SPACING),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(READER_STATUS_ITEM_SPACING),
            ) {
                Box(
                    modifier =
                        Modifier
                            .size(READER_STATUS_INDICATOR_SIZE)
                            .background(statusColor, CircleShape),
                )
                Column {
                    Text(
                        text = stringResource(R.string.usb_reader),
                        fontWeight = FontWeight.SemiBold,
                        style = MaterialTheme.typography.titleLarge,
                    )
                    Text(
                        text = statusTitle,
                        color = statusColor,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }

            if (
                snapshot.status == ReaderConnectionStatus.READY &&
                snapshot.cardPresence != null
            ) {
                HorizontalDivider()
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = stringResource(R.string.card),
                        style = MaterialTheme.typography.bodyLarge,
                    )
                    Text(
                        text =
                            when (snapshot.cardPresence) {
                                CardPresence.PRESENT -> {
                                    stringResource(R.string.present)
                                }

                                CardPresence.NOT_PRESENT -> {
                                    stringResource(R.string.not_present)
                                }
                            },
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.bodyLarge,
                    )
                }
            }

            if (
                snapshot.status == ReaderConnectionStatus.PERMISSION_REQUIRED ||
                snapshot.status == ReaderConnectionStatus.PERMISSION_REQUEST_FAILED ||
                snapshot.status == ReaderConnectionStatus.CARD_ERROR ||
                snapshot.status == ReaderConnectionStatus.TRANSPORT_ERROR
            ) {
                Button(
                    onClick = onRequestPermission,
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .testTag(UiAutomationIds.READER_ACTION),
                ) {
                    Text(
                        if (snapshot.status == ReaderConnectionStatus.TRANSPORT_ERROR) {
                            stringResource(R.string.retry)
                        } else {
                            stringResource(R.string.allow)
                        },
                    )
                }
            }

            if (
                snapshot.status == ReaderConnectionStatus.ACCESS_NUMBER_REQUIRED ||
                snapshot.status == ReaderConnectionStatus.WRONG_ACCESS_NUMBER
            ) {
                HorizontalDivider()
                ReaderCanEntry(onConnect = onConnect)
            }
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun ReaderCanEntry(onConnect: (CanSubmission) -> Unit) {
    val initialCan = remember { fi.refineid.android.core.CanSessionStore.currentCan ?: "" }
    val canState = remember { TextFieldState(initialCan) }

    var remainingCooldown by remember {
        mutableIntStateOf(
            fi.refineid.android.core.CanSessionStore
                .remainingCooldownSeconds(canState.text),
        )
    }
    LaunchedEffect(canState.text) {
        while (true) {
            remainingCooldown =
                fi.refineid.android.core.CanSessionStore
                    .remainingCooldownSeconds(canState.text)
            if (remainingCooldown <= 0) break
            delay(1000L)
        }
    }

    val isCanBlocked = remainingCooldown > 0
    val canReady = CanSubmission.isComplete(canState.text) && !isCanBlocked

    val submit = {
        if (canReady) {
            fi.refineid.android.core.CanSessionStore
                .remember(canState.text)
            val can = CanSubmission.from(canState.text)
            onConnect(can)
        }
        Unit
    }
    SecureTextField(
        state = canState,
        modifier =
            Modifier
                .fillMaxWidth()
                .testTag(UiAutomationIds.READER_CAN_FIELD),
        label = { Text(stringResource(R.string.can)) },
        inputTransformation = CanInputTransformation,
        textObfuscationMode = TextObfuscationMode.Visible,
        keyboardOptions =
            KeyboardOptions(
                autoCorrectEnabled = false,
                keyboardType = KeyboardType.NumberPassword,
                imeAction = ImeAction.Done,
            ),
        isError = isCanBlocked,
        supportingText = {
            if (isCanBlocked) {
                Text(
                    text = stringResource(R.string.can_rejected_cooldown, remainingCooldown),
                    color = MaterialTheme.colorScheme.error,
                )
            }
        },
        onKeyboardAction = { submit() },
    )
    Button(
        onClick = submit,
        modifier =
            Modifier
                .fillMaxWidth()
                .testTag(UiAutomationIds.READER_CONNECT_ACTION),
        enabled = canReady,
    ) {
        Text(stringResource(R.string.unlock))
    }
}

private const val WEIGHT_FILL = 1F

private val SCREEN_HORIZONTAL_PADDING = 24.dp
private val SCREEN_VERTICAL_PADDING = 28.dp
private val SCREEN_ITEM_SPACING = 28.dp
private val CARD_PADDING = 20.dp
private val CARD_ITEM_SPACING = 14.dp
private val CARD_CORNER_RADIUS = 22.dp
private val CARD_ELEVATION = 2.dp
private val READER_STATUS_ITEM_SPACING = 12.dp
private val READER_STATUS_INDICATOR_SIZE = 12.dp

private val MinusCircleIcon: ImageVector by lazy {
    ImageVector
        .Builder(
            name = "MinusCircle",
            defaultWidth = 24.dp,
            defaultHeight = 24.dp,
            viewportWidth = 24f,
            viewportHeight = 24f,
        ).addPath(
            pathData =
                PathParser()
                    .parsePathString(
                        "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18" +
                            "c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-5-9h10v2H7z",
                    ).toNodes(),
            fill = SolidColor(Color.Black),
        ).build()
}
