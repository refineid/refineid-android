// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import fi.refineid.android.core.NativeCardKeyProfile
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class RappEcdsaWireSignatureTest {
    private fun der(
        r: ByteArray,
        s: ByteArray,
    ): ByteArray {
        val body = byteArrayOf(INTEGER, r.size.toByte()) + r + byteArrayOf(INTEGER, s.size.toByte()) + s
        val header =
            if (body.size < LONG_FORM) {
                byteArrayOf(SEQUENCE, body.size.toByte())
            } else {
                byteArrayOf(SEQUENCE, ONE_LENGTH_BYTE, body.size.toByte())
            }
        return header + body
    }

    @Test
    fun coordinateSizesFollowTheKeyProfile() {
        assertEquals(P256, RappEcdsaWireSignature.coordinateBytes(NativeCardKeyProfile.ECDSA_P256))
        assertEquals(P384, RappEcdsaWireSignature.coordinateBytes(NativeCardKeyProfile.ECDSA_P384))
        assertNull(RappEcdsaWireSignature.coordinateBytes(NativeCardKeyProfile.RSA_2048))
        assertNull(RappEcdsaWireSignature.coordinateBytes(NativeCardKeyProfile.RSA_3072))
    }

    @Test
    fun fixedWidthInputPassesThroughEvenWhenItLooksLikeDer() {
        val raw = ByteArray(2 * P384) { 0x30 }
        assertArrayEquals(raw, RappEcdsaWireSignature.toRaw(raw, P384))
    }

    @Test
    fun derWithShortCoordinatesIsLeftPadded() {
        val r = byteArrayOf(0x01, 0x02)
        val s = byteArrayOf(SHORT_S)
        val raw = RappEcdsaWireSignature.toRaw(der(r, s), P256)
        val expected = ByteArray(2 * P256)
        expected[P256 - 2] = 0x01
        expected[P256 - 1] = 0x02
        expected[2 * P256 - 1] = SHORT_S
        assertArrayEquals(expected, raw)
    }

    @Test
    fun derPositivePrefixIsStripped() {
        val r = byteArrayOf(0x00) + ByteArray(P384) { 0x80.toByte() }
        val s = byteArrayOf(0x00) + ByteArray(P384) { 0xff.toByte() }
        val raw = RappEcdsaWireSignature.toRaw(der(r, s), P384)
        assertArrayEquals(ByteArray(P384) { 0x80.toByte() } + ByteArray(P384) { 0xff.toByte() }, raw)
    }

    @Test
    fun coordinateWiderThanTheCurveIsRefused() {
        val wide = ByteArray(P256 + 1) { 0x11 }
        assertThrows(IllegalArgumentException::class.java) {
            RappEcdsaWireSignature.toRaw(der(wide, byteArrayOf(0x01)), P256)
        }
    }

    @Test
    fun malformedAndTrailingInputIsRefused() {
        assertThrows(IllegalArgumentException::class.java) {
            RappEcdsaWireSignature.toRaw(byteArrayOf(SEQUENCE, INTEGER, INTEGER), P256)
        }
        assertThrows(IllegalArgumentException::class.java) {
            RappEcdsaWireSignature.toRaw(der(byteArrayOf(0x01), byteArrayOf(0x02)) + byteArrayOf(0x00), P256)
        }
    }

    private companion object {
        const val P256 = 32
        const val SHORT_S: Byte = 0x7f
        const val P384 = 48
        const val SEQUENCE: Byte = 0x30
        const val INTEGER: Byte = 0x02
        const val ONE_LENGTH_BYTE: Byte = 0x81.toByte()
        const val LONG_FORM = 0x80
    }
}
