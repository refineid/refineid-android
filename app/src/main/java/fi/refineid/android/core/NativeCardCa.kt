package fi.refineid.android.core

/**
 * Native bridge for reading and caching card-delivered Root and Intermediate CA
 * certificates.
 */
internal object NativeCardCa {
    fun readRootCaCertificate(): ByteArray? =
        if (!NativeCore.isLoaded) {
            null
        } else {
            try {
                val bytes = readCardRootCaCertificateNative()
                bytes.takeIf { it.isNotEmpty() }
            } catch (_: LinkageError) {
                null
            } catch (_: RuntimeException) {
                null
            }
        }

    fun readIntermediateCaCertificate(): ByteArray? =
        if (!NativeCore.isLoaded) {
            null
        } else {
            try {
                val bytes = readCardIntermediateCaCertificateNative()
                bytes.takeIf { it.isNotEmpty() }
            } catch (_: LinkageError) {
                null
            } catch (_: RuntimeException) {
                null
            }
        }

    fun setCachedCaCertificates(
        rootCa: ByteArray?,
        intermediateCa: ByteArray?,
    ): Boolean =
        if (!NativeCore.isLoaded) {
            false
        } else {
            try {
                val rootBytes = rootCa ?: ByteArray(0)
                val intermediateBytes = intermediateCa ?: ByteArray(0)
                setCachedCaCertificatesNative(rootBytes, intermediateBytes) == 1
            } catch (_: LinkageError) {
                false
            } catch (_: RuntimeException) {
                false
            }
        }

    /** What the card answered to the last read of each on-card CA certificate. */
    fun lastReadAnswers(): List<CardCaReadAnswer> =
        CardCaFile.entries.map { file ->
            val encoded =
                if (!NativeCore.isLoaded) {
                    CardCaReadAnswer.NOT_ASKED_ENCODING
                } else {
                    try {
                        lastCaReadAnswerNative(file.slot)
                    } catch (_: LinkageError) {
                        CardCaReadAnswer.NOT_ASKED_ENCODING
                    } catch (_: RuntimeException) {
                        CardCaReadAnswer.NOT_ASKED_ENCODING
                    }
                }
            CardCaReadAnswer.decode(file, encoded)
        }

    @JvmStatic
    private external fun lastCaReadAnswerNative(slot: Int): Int

    @JvmStatic
    private external fun readCardRootCaCertificateNative(): ByteArray

    @JvmStatic
    private external fun readCardIntermediateCaCertificateNative(): ByteArray

    @JvmStatic
    private external fun setCachedCaCertificatesNative(
        rootCa: ByteArray,
        intermediateCa: ByteArray,
    ): Int
}

/** The on-card CA certificates, in the native bridge's slot order. */
internal enum class CardCaFile(
    val slot: Int,
) {
    /** EF.4334, the root. */
    ROOT_CA(slot = 0),

    /** EF.4336, the issuing CA. */
    ISSUING_CA(slot = 1),
}

/** The command of a CA certificate read the card answered last. */
internal enum class CardCaReadStep(
    val code: Int,
) {
    NOT_ASKED(code = 0),
    SELECT_MF(code = 1),
    SELECT_FILE(code = 2),
    READ_BINARY(code = 3),

    /** The bytes read are not a CA certificate. */
    CERTIFICATE(code = 4),

    /** The read completed. */
    READ(code = 5),
}

/**
 * What the card answered to the read of one CA certificate: the step it
 * stopped at, and its status word when it gave one.
 */
internal data class CardCaReadAnswer(
    val file: CardCaFile,
    val step: CardCaReadStep,
    val statusWord: Int?,
) {
    val isRead: Boolean
        get() = step == CardCaReadStep.READ

    companion object {
        const val NOT_ASKED_ENCODING = 0
        private const val STEP_FACTOR = 0x1_0000
        private const val NO_STATUS_WORD = 0

        /** The native encoding is `step * 0x10000 + status word`, with no status word as 0. */
        fun decode(
            file: CardCaFile,
            encoded: Int,
        ): CardCaReadAnswer {
            val step = CardCaReadStep.entries.firstOrNull { it.code == encoded / STEP_FACTOR }
            val status = encoded % STEP_FACTOR
            return if (step == null || encoded < NOT_ASKED_ENCODING) {
                CardCaReadAnswer(file, CardCaReadStep.NOT_ASKED, null)
            } else {
                CardCaReadAnswer(file, step, status.takeUnless { it == NO_STATUS_WORD })
            }
        }
    }
}
