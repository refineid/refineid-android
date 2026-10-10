// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import fi.refineid.android.core.NativeCardKeyProfile

/**
 * The RAPP wire form of an ECDSA signature (RAPP v26.10.9 section 9.2):
 * fixed-width big-endian `r || s`, each coordinate left-padded to the curve
 * size, never DER.
 */
internal object RappEcdsaWireSignature {
    private const val P256_COORDINATE_BYTES = 32
    private const val P384_COORDINATE_BYTES = 48
    private const val SEQUENCE_TAG = 0x30
    private const val INTEGER_TAG = 0x02
    private const val LONG_FORM_BIT = 0x80
    private const val ONE_LENGTH_BYTE = 0x81
    private const val BYTE_MASK = 0xFF
    private const val COORDINATE_COUNT = 2

    /** The coordinate size of an ECDSA key profile, or null for RSA. */
    fun coordinateBytes(keyProfile: NativeCardKeyProfile): Int? =
        when (keyProfile) {
            NativeCardKeyProfile.ECDSA_P256 -> P256_COORDINATE_BYTES
            NativeCardKeyProfile.ECDSA_P384 -> P384_COORDINATE_BYTES
            NativeCardKeyProfile.RSA_2048, NativeCardKeyProfile.RSA_3072 -> null
        }

    /**
     * [signature] as fixed-width `r || s` for a curve of [coordinateBytes].
     * Accepts the fixed-width form itself or a DER `ECDSA-Sig-Value`.
     *
     * @throws IllegalArgumentException when the signature is neither, or a
     *   coordinate is wider than the curve.
     */
    fun toRaw(
        signature: ByteArray,
        coordinateBytes: Int,
    ): ByteArray {
        if (signature.size == COORDINATE_COUNT * coordinateBytes) {
            return signature.copyOf()
        }
        val reader = DerReader(signature)
        reader.expectTag(SEQUENCE_TAG)
        val sequenceEnd = reader.readLength() + reader.offset
        require(sequenceEnd == signature.size) { "ECDSA signature has trailing bytes" }
        val raw = ByteArray(COORDINATE_COUNT * coordinateBytes)
        for (index in 0 until COORDINATE_COUNT) {
            reader.expectTag(INTEGER_TAG)
            val length = reader.readLength()
            val integer = reader.take(length)
            val magnitude = integer.dropWhile { it == 0.toByte() }.toByteArray()
            require(magnitude.size <= coordinateBytes) { "ECDSA coordinate is wider than the curve" }
            magnitude.copyInto(raw, destinationOffset = (index + 1) * coordinateBytes - magnitude.size)
        }
        require(reader.offset == signature.size) { "ECDSA signature has trailing bytes" }
        return raw
    }

    private class DerReader(
        private val bytes: ByteArray,
    ) {
        var offset = 0
            private set

        fun expectTag(tag: Int) {
            require(offset < bytes.size && (bytes[offset].toInt() and BYTE_MASK) == tag) { "unexpected DER tag" }
            offset++
        }

        fun readLength(): Int {
            require(offset < bytes.size) { "truncated DER length" }
            val first = bytes[offset++].toInt() and BYTE_MASK
            if (first and LONG_FORM_BIT == 0) return first
            require(first == ONE_LENGTH_BYTE && offset < bytes.size) { "unsupported DER length" }
            return bytes[offset++].toInt() and BYTE_MASK
        }

        fun take(length: Int): ByteArray {
            require(length > 0 && offset + length <= bytes.size) { "truncated DER integer" }
            return bytes.copyOfRange(offset, offset + length).also { offset += length }
        }
    }
}
