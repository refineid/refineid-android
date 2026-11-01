package fi.refineid.android.diagnostics

import fi.refineid.android.core.CardActivationNeeds
import fi.refineid.android.core.CardManagementScheme
import fi.refineid.android.core.CredentialHealth
import fi.refineid.android.core.NativePin1State
import fi.refineid.android.core.NativePin2State
import fi.refineid.android.core.NativePinReferenceScheme
import fi.refineid.android.core.PersonCardDetails
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DiagnosticsReportTest {
    private fun health(
        numbering: NativePinReferenceScheme,
        scheme: CardManagementScheme,
    ): CredentialHealth =
        CredentialHealth(
            pin1State = NativePin1State.Locked,
            pin2State = NativePin2State.Locked,
            pukState = NativePin1State.NoInformation,
            scheme = numbering,
            activationScheme = scheme,
            activationNeeds = CardActivationNeeds(pin1 = true, pin2 = true),
        )

    @Test
    fun reportsTheNativeNumberingAndScheme() {
        val organization =
            cardStatusText(
                cardDetails = null,
                credentialHealth = health(NativePinReferenceScheme.ORGANIZATIONAL, CardManagementScheme.PUK),
            )
        assertTrue(organization.contains("Numbering: organization (FINEID S4-2 section 4.2)"))
        assertTrue(organization.contains("Activation scheme: activation PIN is the PUK (FINEID S4-1 section 4.6.1)"))

        val citizen =
            cardStatusText(
                cardDetails = null,
                credentialHealth = health(NativePinReferenceScheme.CITIZEN, CardManagementScheme.PRESET_PIN),
            )
        assertTrue(citizen.contains("Numbering: citizen (FINEID S1)"))
        assertTrue(citizen.contains("Activation scheme: preset activation PIN (FINEID S4-1 section 4.6.2)"))

        val undecided =
            cardStatusText(
                cardDetails = null,
                credentialHealth = health(NativePinReferenceScheme.CITIZEN, CardManagementScheme.UNKNOWN),
            )
        assertTrue(undecided.contains("Activation scheme: none decided"))
    }

    @Test
    fun cardStatusOmitsHolderIdentity() {
        val details =
            PersonCardDetails(
                holderName = "Test Holder 010280-123A",
                fullName = "Test Holder",
                issuedDate = "14.1.2026",
                expiryDate = "14.1.2031",
                issuer = "Test Issuer",
                signatureAlgorithm = "SHA384withECDSA",
            )

        val status = cardStatusText(details, credentialHealth = null)

        assertFalse(status.contains("Holder:"))
        assertFalse(status.contains("Valid:"))
        assertFalse(status.contains("Test Holder"))
        assertFalse(status.contains("14.1.2026"))
        assertFalse(status.contains("14.1.2031"))
        assertFalse(status.contains("Generation"))
        assertTrue(status.contains("Issuer: Test Issuer"))
    }

    @Test
    fun cardStatusWithoutDetailsOrProbeOmitsIdentity() {
        val status = cardStatusText(cardDetails = null, credentialHealth = null)

        assertFalse(status.contains("Holder:"))
        assertFalse(status.contains("Valid:"))
        assertTrue(status.contains("Numbering: (not probed)"))
        assertTrue(status.contains("Activation scheme: (not probed)"))
    }
}
