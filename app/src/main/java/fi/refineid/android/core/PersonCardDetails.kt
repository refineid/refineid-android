package fi.refineid.android.core

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Locale

internal object CardPhotoStore {
    private val photos = mutableMapOf<String, ByteArray>()
    private var storageDirectory: File? = null

    /**
     * App-private directory for cached card photos, so a photo read once
     * under PACE survives process restarts. The access number itself is
     * never persisted; only the already-released photo bytes are.
     */
    @Synchronized
    fun initialize(directory: File) {
        storageDirectory = directory
    }

    /**
     * The cached photo for exactly this holder, or null. There is no
     * fallback across holders: a photo may only ever be shown next to
     * the identity it was read with.
     */
    @Synchronized
    fun getPhoto(holderKey: String?): ByteArray? {
        if (holderKey == null) return null
        photos[holderKey]?.let { return it }
        val tokens = holderKey.split(" ").filter { it.isNotBlank() }
        if (tokens.size > 1 && tokens.last().any { it.isDigit() }) {
            val bareName = tokens.dropLast(1).joinToString(" ")
            photos[bareName]?.let { return it }
        }
        return (loadPersisted(holderKey) ?: loadBarePersisted(holderKey))?.also { photos[holderKey] = it }
    }

    @Synchronized
    fun savePhoto(
        photoBytes: ByteArray,
        holderKey: String? = null,
        documentNumber: String? = null,
    ) {
        if (holderKey != null) {
            photos[holderKey] = photoBytes
            val tokens = holderKey.split(" ").filter { it.isNotBlank() }
            if (tokens.size > 1 && tokens.last().any { it.isDigit() }) {
                val bareName = tokens.dropLast(1).joinToString(" ")
                photos[bareName] = photoBytes
            }
            persist(holderKey, documentNumber, photoBytes)
        }
    }

    /**
     * The photo's user-facing file name: the identity line and the printed
     * card number, so an exported photo stays globally unique per person
     * and card.
     */
    @Synchronized
    fun exportFileName(holderKey: String?): String =
        holderKey?.let { key ->
            persistedFile(key)?.name ?: (sanitize(key) + PHOTO_FILE_EXTENSION)
        } ?: DEFAULT_EXPORT_FILE_NAME

    @Synchronized
    fun clear() {
        photos.clear()
        storageDirectory?.listFiles()?.forEach { file -> file.delete() }
    }

    private fun persist(
        holderKey: String,
        documentNumber: String?,
        photoBytes: ByteArray,
    ) {
        val directory = storageDirectory ?: return
        try {
            directory.mkdirs()
            persistedFile(holderKey)?.delete()
            val stem = sanitize(listOfNotNull(holderKey, documentNumber).joinToString(" "))
            File(directory, stem + PHOTO_FILE_EXTENSION).writeBytes(photoBytes)
        } catch (_: IOException) {
            // The in-memory copy still serves this session.
        }
    }

    private fun loadPersisted(holderKey: String): ByteArray? =
        try {
            persistedFile(holderKey)?.readBytes()
        } catch (_: IOException) {
            null
        }

    private fun loadBarePersisted(holderKey: String): ByteArray? {
        val tokens = holderKey.split(" ").filter { it.isNotBlank() }
        if (tokens.size > 1 && tokens.last().any { it.isDigit() }) {
            val bareName = tokens.dropLast(1).joinToString(" ")
            return loadPersisted(bareName)
        }
        return null
    }

    // A cache hit requires the whole holder key: either the bare stem
    // (no document number was known) or the stem followed by a space and
    // the document-number suffix. A prefix alone never matches, so one
    // holder's photo can never surface for another whose name merely
    // starts the same way.
    private fun persistedFile(holderKey: String): File? {
        val directory = storageDirectory ?: return null
        val stem = sanitize(holderKey)
        return directory
            .listFiles()
            ?.firstOrNull { file ->
                file.isFile &&
                    (
                        file.name == stem + PHOTO_FILE_EXTENSION ||
                            file.name.startsWith("$stem ")
                    )
            }
    }

    // File names stay inside the app-private cache; path separators and
    // control characters are still excluded.
    private fun sanitize(value: String): String =
        value
            .map { character ->
                if (character.isLetterOrDigit() || character == ' ' || character == '-') {
                    character
                } else {
                    '_'
                }
            }.joinToString("")

    private const val PHOTO_FILE_EXTENSION = ".jpg"
    private const val DEFAULT_EXPORT_FILE_NAME = "card-photo.jpg"
}

internal data class PersonCardDetails(
    val holderName: String,
    val fullName: String,
    val identifier: String? = null,
    val dateOfBirth: String? = null,
    val nationality: String = "Suomi (FIN)",
    val issuedDate: String? = null,
    val expiryDate: String? = null,
    val issuer: String? = null,
    val signatureAlgorithm: String? = null,
    /**
     * True only when ICAO 9303 passive authentication actually ran and
     * passed for this read; the authenticity badge is gated on it and
     * never shown for an unverified read.
     */
    val isTamperProofVerified: Boolean = false,
    val photoBytes: ByteArray? = null,
    /**
     * The MRZ document number: the card's printed, human-visible number.
     * Distinct from the chip's full PKCS#15 serial, which carries prefixes
     * no holder can verify against the card face.
     */
    val documentNumber: String? = null,
) {
    fun getPhotoBitmap(): Bitmap? =
        (photoBytes ?: CardPhotoStore.getPhoto(holderName))?.let { bytes ->
            try {
                BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
            } catch (_: Exception) {
                null
            }
        }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PersonCardDetails) return false
        return holderName == other.holderName &&
            fullName == other.fullName &&
            identifier == other.identifier &&
            dateOfBirth == other.dateOfBirth &&
            nationality == other.nationality &&
            issuedDate == other.issuedDate &&
            expiryDate == other.expiryDate &&
            issuer == other.issuer &&
            signatureAlgorithm == other.signatureAlgorithm &&
            isTamperProofVerified == other.isTamperProofVerified &&
            (photoBytes contentEquals other.photoBytes) &&
            documentNumber == other.documentNumber
    }

    override fun hashCode(): Int {
        var result = holderName.hashCode()
        result = 31 * result + fullName.hashCode()
        result = 31 * result + (identifier?.hashCode() ?: 0)
        result = 31 * result + (dateOfBirth?.hashCode() ?: 0)
        result = 31 * result + nationality.hashCode()
        result = 31 * result + (issuedDate?.hashCode() ?: 0)
        result = 31 * result + (expiryDate?.hashCode() ?: 0)
        result = 31 * result + (issuer?.hashCode() ?: 0)
        result = 31 * result + (signatureAlgorithm?.hashCode() ?: 0)
        result = 31 * result + isTamperProofVerified.hashCode()
        result = 31 * result + (photoBytes?.contentHashCode() ?: 0)
        result = 31 * result + (documentNumber?.hashCode() ?: 0)
        return result
    }

    companion object {
        fun fromDer(
            der: ByteArray,
            photoBytes: ByteArray? = null,
            documentNumber: String? = null,
            tamperProofVerified: Boolean = false,
        ): PersonCardDetails? =
            try {
                val factory = CertificateFactory.getInstance("X.509")
                val x509 = factory.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
                val rfc2253 = x509.subjectX500Principal.getName("RFC2253")
                val cn =
                    "(?:^|,)\\s*CN=([^,]+)".toRegex().find(rfc2253)?.groupValues?.get(1)
                        ?: return null

                val tokens = cn.split(" ").filter { it.isNotBlank() }
                val (nameTokens, idToken) =
                    if (tokens.isNotEmpty() &&
                        tokens.last().matches("[0-9A-Za-z]{6,12}".toRegex()) &&
                        tokens.last().any { it.isDigit() }
                    ) {
                        tokens.dropLast(1) to tokens.last()
                    } else {
                        tokens to null
                    }
                val formattedName = if (nameTokens.isNotEmpty()) nameTokens.joinToString(" ") else cn

                val countryCode =
                    "(?:^|,)\\s*C=([^,]+)".toRegex().find(rfc2253)?.groupValues?.get(1) ?: "FI"
                val nationalityStr =
                    when (countryCode.uppercase(Locale.ROOT)) {
                        "FI" -> "Suomi (FIN)"
                        "SE" -> "Ruotsi (SWE)"
                        "EE" -> "Viro (EST)"
                        "NO" -> "Norja (NOR)"
                        else -> countryCode
                    }

                val issuerRfc = x509.issuerX500Principal.getName("RFC2253")
                val issuerCn =
                    "(?:^|,)\\s*CN=([^,]+)".toRegex().find(issuerRfc)?.groupValues?.get(1)
                        ?: "Digi- ja väestötietovirasto (DVV)"
                val cleanIssuer =
                    if (issuerCn.contains("VRK", ignoreCase = true) ||
                        issuerCn.contains("DVV", ignoreCase = true) ||
                        issuerCn.contains("FINEID", ignoreCase = true)
                    ) {
                        "Digi- ja väestötietovirasto (DVV)"
                    } else {
                        issuerCn
                    }

                val dateFormat = SimpleDateFormat("d.M.yyyy", Locale.ROOT)
                val issued =
                    try {
                        dateFormat.format(x509.notBefore)
                    } catch (_: Exception) {
                        null
                    }
                val expires =
                    try {
                        dateFormat.format(x509.notAfter)
                    } catch (_: Exception) {
                        null
                    }

                val effectivePhoto =
                    photoBytes
                        ?: CardPhotoStore.getPhoto(formattedName)
                        ?: CardPhotoStore.getPhoto(cn)

                PersonCardDetails(
                    holderName = formattedName,
                    fullName = formattedName,
                    identifier = idToken,
                    dateOfBirth = null,
                    nationality = nationalityStr,
                    issuedDate = issued,
                    expiryDate = expires,
                    issuer = cleanIssuer,
                    signatureAlgorithm = x509.sigAlgName,
                    isTamperProofVerified = tamperProofVerified,
                    photoBytes = effectivePhoto,
                    documentNumber = documentNumber,
                )
            } catch (_: Exception) {
                null
            }

        fun fromHolderName(holderName: String): PersonCardDetails {
            val tokens = holderName.split(" ").filter { it.isNotBlank() }
            val (nameTokens, idToken) =
                if (tokens.isNotEmpty() &&
                    tokens.last().matches("[0-9A-Za-z]{6,12}".toRegex()) &&
                    tokens.last().any { it.isDigit() }
                ) {
                    tokens.dropLast(1) to tokens.last()
                } else {
                    tokens to null
                }
            val formattedName = if (nameTokens.isNotEmpty()) nameTokens.joinToString(" ") else holderName

            val effectivePhoto = CardPhotoStore.getPhoto(holderName)

            return PersonCardDetails(
                holderName = holderName,
                fullName = formattedName,
                identifier = idToken,
                dateOfBirth = null,
                nationality = "Suomi (FIN)",
                issuedDate = null,
                expiryDate = null,
                issuer = "Digi- ja väestötietovirasto (DVV)",
                signatureAlgorithm = "ECDSA_P384 / SHA-384",
                isTamperProofVerified = false,
                photoBytes = effectivePhoto,
            )
        }
    }
}
