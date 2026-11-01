package fi.refineid.android.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class NativeCardSessionMaterialTest {
    @Test
    fun replacementAndCloseEraseOwnedCertificateMaterial() {
        val material = NativeCardSessionMaterial()
        val first = certificate(FIRST_DER_BYTE)
        val second = certificate(SECOND_DER_BYTE)

        material.cacheAuthenticationCertificate(first)
        assertArrayEquals(byteArrayOf(FIRST_DER_BYTE), first.copyDer())

        material.cacheAuthenticationCertificate(second)
        assertThrows(IllegalStateException::class.java) {
            first.copyDer()
        }
        assertArrayEquals(
            byteArrayOf(SECOND_DER_BYTE),
            material.requireAuthenticationCertificate().copyDer(),
        )

        material.close()
        material.close()
        assertThrows(IllegalStateException::class.java) {
            second.copyDer()
        }
        assertThrows(IllegalStateException::class.java) {
            material.requireAuthenticationCertificate()
        }
    }

    @Test
    fun preflightBelongsToTheSameSessionLifecycle() {
        val material = NativeCardSessionMaterial()
        val preflight =
            NativePin1Preflight(
                referenceScheme = NativePinReferenceScheme.ORGANIZATIONAL,
                state = NativePin1State.Remaining(SAFE_RETRY_COUNT),
                retryFloorPermits = true,
            )

        material.cachePin1Preflight(preflight)
        assertEquals(preflight, material.requirePin1Preflight())

        material.close()
        assertThrows(IllegalStateException::class.java) {
            material.requirePin1Preflight()
        }
        assertThrows(IllegalStateException::class.java) {
            material.cachePin1Preflight(preflight)
        }
    }

    @Test
    fun anAcceptedPin1ReadsAtTheTryLimitUntilAnotherPinCommandLeaves() {
        val material = NativeCardSessionMaterial()
        material.cachePin1Preflight(opened(NativePin1State.Remaining(FINEID_PIN_TRY_LIMIT)))

        material.pin1CountUnknown()
        assertNull("a PIN command in flight leaves the count unknown", attemptsLeft(material))
        material.pin1Accepted()
        assertEquals(FINEID_PIN_TRY_LIMIT, attemptsLeft(material))

        // A PIN 2 signature or a card-management command on the same channel.
        material.pin1CountUnknown()
        assertNull(attemptsLeft(material))

        material.cachePin1Preflight(opened(NativePin1State.Remaining(SAFE_RETRY_COUNT)))
        assertEquals("a fresh open reads the card again", SAFE_RETRY_COUNT, attemptsLeft(material))
    }

    @Test
    fun anAcceptedPin1RestoresTheTryLimitAfterSpentAttempts() {
        val material = NativeCardSessionMaterial()
        material.cachePin1Preflight(opened(NativePin1State.Remaining(SAFE_RETRY_COUNT)))

        material.pin1CountUnknown()
        material.pin1Accepted()

        assertEquals(FINEID_PIN_TRY_LIMIT, attemptsLeft(material))
    }

    @Test
    fun countChangesNeedAnOpenedPreflight() {
        val material = NativeCardSessionMaterial()

        material.pin1Accepted()
        material.pin1CountUnknown()

        assertNull(material.cachedPin1Preflight())
    }

    private fun attemptsLeft(material: NativeCardSessionMaterial): Int? =
        material.cachedPin1Preflight()?.state?.attemptsLeft()

    private fun opened(state: NativePin1State): NativePin1Preflight =
        NativePin1Preflight(
            referenceScheme = NativePinReferenceScheme.CITIZEN,
            state = state,
            retryFloorPermits = true,
        )

    private fun certificate(byte: Byte): NativeAuthenticationCertificate =
        NativeAuthenticationCertificate(
            keyProfile = NativeCardKeyProfile.RSA_2048,
            ownedDer = byteArrayOf(byte),
        )

    private companion object {
        const val FIRST_DER_BYTE: Byte = 0x30
        const val SECOND_DER_BYTE: Byte = 0x31
        const val SAFE_RETRY_COUNT = 3
    }
}
