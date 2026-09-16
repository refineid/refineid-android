@file:Suppress("LongMethod", "MagicNumber", "MaxLineLength")

package fi.refineid.android.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.net.Uri
import android.widget.Toast
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.PathParser
import androidx.compose.ui.layout.Layout
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Constraints
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import androidx.core.graphics.createBitmap
import fi.refineid.android.R
import fi.refineid.android.core.CardPhotoStore
import fi.refineid.android.core.PersonCardDetails
import java.io.File
import java.io.FileOutputStream

@Suppress("FunctionName", "ktlint:standard:function-naming", "LongMethod")
@Composable
internal fun PersonScreen(
    details: PersonCardDetails,
    modifier: Modifier = Modifier,
    activationRequired: Boolean = false,
    onActivate: (() -> Unit)? = null,
    onReadPhoto: (((ByteArray?) -> Unit) -> Unit)? = null,
) {
    val context = LocalContext.current
    var onDemandPhotoBytes by remember(details.holderName) { mutableStateOf<ByteArray?>(null) }
    val currentPhotoBytes =
        details.photoBytes
            ?: onDemandPhotoBytes
            ?: CardPhotoStore.getPhoto(details.holderName)
    var isLoadingPhoto by remember { mutableStateOf(false) }

    val photoBitmap =
        remember(currentPhotoBytes) {
            currentPhotoBytes?.let { bytes ->
                try {
                    BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                } catch (_: Exception) {
                    null
                }
            }
        }

    fun requestPhoto(andAction: ((Bitmap, ByteArray) -> Unit)? = null) {
        val existingBytes = currentPhotoBytes
        if (existingBytes != null) {
            val bitmap =
                photoBitmap ?: try {
                    BitmapFactory.decodeByteArray(existingBytes, 0, existingBytes.size)
                } catch (_: Exception) {
                    null
                }
            if (bitmap != null && andAction != null) {
                andAction(bitmap, existingBytes)
            }
            return
        }
        if (isLoadingPhoto) return
        isLoadingPhoto = true
        onReadPhoto?.invoke { bytes ->
            isLoadingPhoto = false
            if (bytes != null && bytes.isNotEmpty()) {
                CardPhotoStore.savePhoto(bytes, details.holderName, details.documentNumber)
                onDemandPhotoBytes = bytes
                val bitmap =
                    try {
                        BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                    } catch (_: Exception) {
                        null
                    }
                if (bitmap != null && andAction != null) {
                    andAction(bitmap, bytes)
                }
            }
        }
    }

    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(SUBSCREEN_ITEM_SPACING),
    ) {
        if (activationRequired) {
            val label = details.holderName.ifBlank { details.fullName.ifBlank { details.documentNumber } }
            ActivationBanner(
                cardLabel = label,
                onActivate = onActivate,
            )
        }

        // Photo Card
        NavigationGroup {
            Column(
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .padding(PHOTO_CARD_PADDING),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(PHOTO_SECTION_SPACING),
            ) {
                if (photoBitmap != null) {
                    Image(
                        bitmap = photoBitmap.asImageBitmap(),
                        contentDescription = stringResource(R.string.section_identity),
                        modifier =
                            Modifier
                                .size(width = PHOTO_WIDTH, height = PHOTO_HEIGHT)
                                .clip(RoundedCornerShape(PHOTO_CORNER_RADIUS))
                                .border(
                                    width = 1.dp,
                                    color = MaterialTheme.colorScheme.outlineVariant,
                                    shape = RoundedCornerShape(PHOTO_CORNER_RADIUS),
                                ),
                    )
                } else {
                    Box(
                        modifier =
                            Modifier
                                .size(width = PHOTO_WIDTH, height = PHOTO_HEIGHT)
                                .clip(RoundedCornerShape(PHOTO_CORNER_RADIUS))
                                .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f))
                                .border(
                                    width = 1.dp,
                                    color = MaterialTheme.colorScheme.outlineVariant,
                                    shape = RoundedCornerShape(PHOTO_CORNER_RADIUS),
                                ).clickable(enabled = !isLoadingPhoto) {
                                    requestPhoto()
                                },
                        contentAlignment = Alignment.Center,
                    ) {
                        if (isLoadingPhoto) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(36.dp),
                                strokeWidth = 3.dp,
                                color = MaterialTheme.colorScheme.primary,
                            )
                        } else {
                            Column(
                                horizontalAlignment = Alignment.CenterHorizontally,
                                verticalArrangement = Arrangement.spacedBy(8.dp),
                            ) {
                                Box(
                                    modifier =
                                        Modifier
                                            .size(AVATAR_CONTAINER_SIZE)
                                            .background(
                                                color = MaterialTheme.colorScheme.primaryContainer,
                                                shape = CircleShape,
                                            ),
                                    contentAlignment = Alignment.Center,
                                ) {
                                    Icon(
                                        imageVector = Icons.Outlined.Person,
                                        contentDescription = null,
                                        tint = MaterialTheme.colorScheme.primary,
                                        modifier = Modifier.size(AVATAR_ICON_SIZE),
                                    )
                                }
                                Text(
                                    text = details.fullName,
                                    style = MaterialTheme.typography.labelMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                }

                AdaptiveButtonRow(modifier = Modifier.fillMaxWidth()) {
                    OutlinedButton(
                        onClick = {
                            if (photoBitmap != null) {
                                copyPhotoToClipboard(context, details, photoBitmap)
                            } else {
                                requestPhoto { bitmap, _ ->
                                    copyPhotoToClipboard(context, details, bitmap)
                                }
                            }
                        },
                        modifier = Modifier.testTag(UiAutomationIds.COPY_PHOTO_ACTION),
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 8.dp),
                        colors = ButtonDefaults.outlinedButtonColors(),
                    ) {
                        Icon(
                            imageVector = CopyIcon,
                            contentDescription = null,
                            modifier = Modifier.size(BUTTON_ICON_SIZE),
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = stringResource(R.string.copy_photo),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }

                    OutlinedButton(
                        onClick = {
                            if (photoBitmap != null) {
                                sharePhoto(context, details, photoBitmap)
                            } else {
                                requestPhoto { bitmap, _ ->
                                    sharePhoto(context, details, bitmap)
                                }
                            }
                        },
                        modifier = Modifier.testTag(UiAutomationIds.SHARE_PHOTO_ACTION),
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 8.dp),
                        colors = ButtonDefaults.outlinedButtonColors(),
                    ) {
                        Icon(
                            imageVector = ShareIcon,
                            contentDescription = null,
                            modifier = Modifier.size(BUTTON_ICON_SIZE),
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = stringResource(R.string.share_photo),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
            }
        }

        // Authenticity badge: shown only when a document-integrity
        // verification actually ran for this read.
        if (details.isTamperProofVerified) {
            NavigationGroup {
                Row(
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .padding(horizontal = ROW_HORIZONTAL_PADDING, vertical = ROW_VERTICAL_PADDING),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(ROW_ITEM_SPACING),
                ) {
                    Icon(
                        imageVector = Icons.Outlined.CheckCircle,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(ROW_ICON_SIZE),
                    )
                    Text(
                        text = stringResource(R.string.card_untampered),
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.Medium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))
    }
}

/**
 * Two action buttons side by side when each fits in half the width,
 * otherwise stacked full-width on their own lines so labels are never
 * truncated to an ellipsis.
 */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun AdaptiveButtonRow(
    modifier: Modifier = Modifier,
    spacing: Dp = BUTTON_ROW_SPACING,
    content: @Composable () -> Unit,
) {
    Layout(
        content = content,
        modifier = modifier,
    ) { measurables, constraints ->
        require(measurables.size == ADAPTIVE_BUTTON_COUNT) {
            "AdaptiveButtonRow expects exactly two buttons"
        }
        val spacingPx = spacing.roundToPx()
        // Intrinsic widths decide the arrangement; each child is measured
        // exactly once, since re-measuring is not allowed.
        val firstIntrinsic = measurables[0].maxIntrinsicWidth(constraints.maxHeight)
        val secondIntrinsic = measurables[1].maxIntrinsicWidth(constraints.maxHeight)
        val maxWidth = constraints.maxWidth
        val halfWidth = (maxWidth - spacingPx) / 2
        if (maxWidth != Constraints.Infinity &&
            halfWidth > 0 &&
            firstIntrinsic <= halfWidth &&
            secondIntrinsic <= halfWidth
        ) {
            val rowConstraints = constraints.copy(minWidth = halfWidth, maxWidth = halfWidth)
            val firstPlaced = measurables[0].measure(rowConstraints)
            val secondPlaced = measurables[1].measure(rowConstraints)
            layout(maxWidth, maxOf(firstPlaced.height, secondPlaced.height)) {
                firstPlaced.placeRelative(0, 0)
                secondPlaced.placeRelative(halfWidth + spacingPx, 0)
            }
        } else {
            val columnConstraints =
                if (maxWidth == Constraints.Infinity) {
                    constraints.copy(minWidth = 0, minHeight = 0)
                } else {
                    constraints.copy(minWidth = maxWidth, maxWidth = maxWidth)
                }
            val firstPlaced = measurables[0].measure(columnConstraints)
            val secondPlaced = measurables[1].measure(columnConstraints)
            val width =
                if (maxWidth == Constraints.Infinity) {
                    maxOf(firstPlaced.width, secondPlaced.width)
                } else {
                    maxWidth
                }
            layout(width, firstPlaced.height + spacingPx + secondPlaced.height) {
                firstPlaced.placeRelative(0, 0)
                secondPlaced.placeRelative(0, firstPlaced.height + spacingPx)
            }
        }
    }
}

private fun copyPhotoToClipboard(
    context: Context,
    details: PersonCardDetails,
    photoBitmap: Bitmap?,
) {
    try {
        val export = savePhotoToShareCache(context, details, photoBitmap)
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newUri(context.contentResolver, export.fileName, export.uri)
        clipboard.setPrimaryClip(clip)
        Toast.makeText(context, context.getString(R.string.photo_copied), Toast.LENGTH_SHORT).show()
    } catch (_: Exception) {
        Toast.makeText(context, "Error copying photo", Toast.LENGTH_SHORT).show()
    }
}

private fun sharePhoto(
    context: Context,
    details: PersonCardDetails,
    photoBitmap: Bitmap?,
) {
    try {
        val export = savePhotoToShareCache(context, details, photoBitmap)
        val shareIntent =
            Intent(Intent.ACTION_SEND).apply {
                type = export.mimeType
                putExtra(Intent.EXTRA_STREAM, export.uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
        context.startActivity(Intent.createChooser(shareIntent, context.getString(R.string.share_photo)))
    } catch (_: Exception) {
        Toast.makeText(context, "Error sharing photo", Toast.LENGTH_SHORT).show()
    }
}

private class PhotoExport(
    val uri: Uri,
    val fileName: String,
    val mimeType: String,
)

// The exported file keeps the card's own image bytes and carries the
// holder identity and printed card number in its name; only the
// placeholder badge is re-encoded.
private fun savePhotoToShareCache(
    context: Context,
    details: PersonCardDetails,
    photoBitmap: Bitmap?,
): PhotoExport {
    val imagesFolder = File(context.cacheDir, "images").apply { mkdirs() }
    val photoBytes = details.photoBytes ?: CardPhotoStore.getPhoto(details.holderName)
    val (file, mimeType) =
        if (photoBytes != null) {
            val name = CardPhotoStore.exportFileName(details.holderName)
            File(imagesFolder, name).apply { writeBytes(photoBytes) } to "image/jpeg"
        } else {
            val bitmap = photoBitmap ?: createPlaceholderBadge(details.fullName)
            val file = File(imagesFolder, "card_photo.png")
            FileOutputStream(file).use { out ->
                bitmap.compress(Bitmap.CompressFormat.PNG, PNG_QUALITY, out)
            }
            file to "image/png"
        }
    return PhotoExport(
        uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file),
        fileName = file.name,
        mimeType = mimeType,
    )
}

private fun createPlaceholderBadge(name: String): Bitmap {
    val bitmap = createBitmap(BADGE_CANVAS_WIDTH, BADGE_CANVAS_HEIGHT)
    val canvas = Canvas(bitmap)
    canvas.drawColor(Color.rgb(BADGE_BG_R, BADGE_BG_G, BADGE_BG_B))

    val paint =
        Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.rgb(BADGE_TEXT_R, BADGE_TEXT_G, BADGE_TEXT_B)
            textSize = BADGE_TEXT_SIZE
            textAlign = Paint.Align.CENTER
        }
    canvas.drawText(name.take(BADGE_MAX_NAME_CHARS), BADGE_TEXT_X, BADGE_TEXT_Y, paint)
    return bitmap
}

private val PHOTO_WIDTH = 130.dp
private val PHOTO_HEIGHT = 160.dp
private val PHOTO_CORNER_RADIUS = 12.dp
private val PHOTO_CARD_PADDING = 16.dp
private val PHOTO_SECTION_SPACING = 16.dp
private val AVATAR_CONTAINER_SIZE = 64.dp
private val AVATAR_ICON_SIZE = 36.dp
private val BUTTON_ICON_SIZE = 18.dp
private val BUTTON_ROW_SPACING = 12.dp

private const val ADAPTIVE_BUTTON_COUNT = 2

private const val BADGE_CANVAS_WIDTH = 300
private const val BADGE_CANVAS_HEIGHT = 380
private const val BADGE_BG_R = 240
private const val BADGE_BG_G = 243
private const val BADGE_BG_B = 246
private const val BADGE_TEXT_R = 0
private const val BADGE_TEXT_G = 102
private const val BADGE_TEXT_B = 204
private const val BADGE_TEXT_SIZE = 32f
private const val BADGE_TEXT_X = 150f
private const val BADGE_TEXT_Y = 200f
private const val BADGE_MAX_NAME_CHARS = 16
private const val PNG_QUALITY = 100

internal val CopyIcon: ImageVector by lazy {
    ImageVector
        .Builder(
            name = "Copy",
            defaultWidth = 24.dp,
            defaultHeight = 24.dp,
            viewportWidth = 24f,
            viewportHeight = 24f,
        ).addPath(
            pathData =
                PathParser()
                    .parsePathString(
                        "M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z",
                    ).toNodes(),
            fill = SolidColor(androidx.compose.ui.graphics.Color.Black),
        ).build()
}

private val ShareIcon: ImageVector by lazy {
    ImageVector
        .Builder(
            name = "Share",
            defaultWidth = 24.dp,
            defaultHeight = 24.dp,
            viewportWidth = 24f,
            viewportHeight = 24f,
        ).addPath(
            pathData =
                PathParser()
                    .parsePathString(
                        "M18 16.08c-.76 0-1.44.3-1.96.77L8.91 12.7c.05-.23.09-.46.09-.7s-.04-.47-.09-.7l7.05-4.11c.54.5 1.25.81 2.04.81 1.66 0 3-1.34 3-3s-1.34-3-3-3-3 1.34-3 3c0 .24.04.47.09.7L8.04 9.81C7.5 9.31 6.79 9 6 9c-1.66 0-3 1.34-3 3s1.34 3 3 3c.79 0 1.5-.31 2.04-.81l7.12 4.16c-.05.21-.08.43-.08.65 0 1.61 1.31 2.92 2.92 2.92 1.61 0 2.92-1.31 2.92-2.92s-1.31-2.92-2.92-2.92z",
                    ).toNodes(),
            fill = SolidColor(androidx.compose.ui.graphics.Color.Black),
        ).build()
}
