package fi.refineid.android.core

/**
 * One manually entered card access number, exactly six digits as
 * printed on the card face (FINEID S4-2). Ownership transfers to at
 * most one holder; every path zeroizes the digits.
 */
internal class CanSubmission private constructor(
    private var ownedBytes: ByteArray?,
) : AutoCloseable {
    /** Transfer the owned digits; the receiver zeroizes them. */
    fun transfer(): ByteArray =
        synchronized(this) {
            checkNotNull(ownedBytes) {
                "CAN submission is no longer available"
            }.also {
                ownedBytes = null
            }
        }

    fun peekDigits(): String? =
        synchronized(this) {
            ownedBytes?.let { String(it, Charsets.US_ASCII) }
        }

    fun copy(): CanSubmission =
        synchronized(this) {
            CanSubmission(checkNotNull(ownedBytes) { "CAN submission is no longer available" }.copyOf())
        }

    override fun close() {
        synchronized(this) {
            ownedBytes?.fill(0)
            ownedBytes = null
        }
    }

    override fun toString(): String = "CanSubmission([redacted])"

    companion object {
        const val CAN_DIGITS = 6

        fun acceptsEntry(input: CharSequence): Boolean = input.length <= CAN_DIGITS && input.all { it in '0'..'9' }

        fun isComplete(input: CharSequence): Boolean = input.length == CAN_DIGITS && acceptsEntry(input)

        fun from(input: CharSequence): CanSubmission {
            require(isComplete(input)) {
                "CAN has an invalid shape"
            }
            val bytes = ByteArray(input.length)
            for (index in input.indices) {
                bytes[index] = input[index].code.toByte()
            }
            return CanSubmission(bytes)
        }
    }
}
