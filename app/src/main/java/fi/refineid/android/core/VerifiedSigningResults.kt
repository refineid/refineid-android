// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fi.refineid.android.core

import fi.refineid.android.diagnostics.AppTrace

/**
 * The card's authentication signature, checked against [certificate] before it
 * is returned, or the coarse failure [nativeResult] named.
 *
 * [paceRejectedFailure] maps a PACE channel refusal onto the session's coarse
 * vocabulary: NFC operations open a PACE channel per call and map a later
 * channel refusal to [AuthenticationSignFailure.TRANSPORT_ERROR], whereas wired
 * and held-session USB signing opens no PACE channel and maps it to
 * [AuthenticationSignFailure.BRIDGE_ERROR].
 */
internal fun verifiedAuthenticationResult(
    certificate: NativeAuthenticationCertificate,
    inputMode: AuthenticationSigningInputMode,
    input: ByteArray,
    nativeResult: NativeAuthenticationSignResult,
    paceRejectedFailure: AuthenticationSignFailure,
): AuthenticationSignResult =
    when (nativeResult) {
        is NativeAuthenticationSignResult.Success -> {
            val isVerified =
                when (inputMode) {
                    AuthenticationSigningInputMode.MESSAGE -> {
                        AuthenticationSignatureVerifier.verify(
                            certificate = certificate,
                            message = input,
                            signature = nativeResult.signature,
                        )
                    }

                    AuthenticationSigningInputMode.PREHASHED -> {
                        AuthenticationSignatureVerifier.verifyPrehashed(
                            certificate = certificate,
                            digest = input,
                            signature = nativeResult.signature,
                        )
                    }
                }
            AppTrace.authenticationSignatureVerificationCompleted(
                inputMode = inputMode,
                isVerified = isVerified,
            )
            if (isVerified) {
                AuthenticationSignResult.Success(nativeResult.signature)
            } else {
                nativeResult.signature.close()
                AuthenticationSignResult.Failure(AuthenticationSignFailure.LOCAL_VERIFICATION_FAILED)
            }
        }

        is NativeAuthenticationSignResult.Failure -> {
            AuthenticationSignResult.Failure(
                kind = nativeResult.kind.toAuthenticationFailure(paceRejectedFailure),
                remainingRetries = nativeResult.remainingRetries,
            )
        }
    }

/**
 * The card's qualified signature, checked against [expectedCertificate] before
 * it is returned, or the coarse failure [nativeResult] named.
 */
internal fun verifiedQualifiedResult(
    expectedCertificate: NativeQualifiedCertificate,
    inputMode: QualifiedSigningInputMode,
    input: ByteArray,
    nativeResult: NativeQualifiedSignResult,
): QualifiedSignResult =
    when (nativeResult) {
        is NativeQualifiedSignResult.Success -> {
            val isVerified =
                when (inputMode) {
                    QualifiedSigningInputMode.MESSAGE -> {
                        QualifiedSignatureVerifier.verify(
                            certificate = expectedCertificate,
                            content = input,
                            signature = nativeResult.signature,
                        )
                    }

                    QualifiedSigningInputMode.PREHASHED -> {
                        QualifiedSignatureVerifier.verifyPrehashed(
                            certificate = expectedCertificate,
                            digest = input,
                            signature = nativeResult.signature,
                        )
                    }
                }
            AppTrace.qualifiedSignatureVerificationCompleted(isVerified)
            if (isVerified) {
                QualifiedSignResult.Success(nativeResult.signature)
            } else {
                nativeResult.signature.close()
                QualifiedSignResult.Failure(QualifiedSignFailure.LOCAL_VERIFICATION_FAILED)
            }
        }

        is NativeQualifiedSignResult.Failure -> {
            QualifiedSignResult.Failure(
                kind = nativeResult.kind.toQualifiedFailure(),
                remainingRetries = nativeResult.remainingRetries,
            )
        }
    }

private fun NativeAuthenticationSignFailure.toAuthenticationFailure(
    paceRejectedFailure: AuthenticationSignFailure,
): AuthenticationSignFailure =
    when (this) {
        NativeAuthenticationSignFailure.CARD_UNAVAILABLE -> AuthenticationSignFailure.CARD_UNAVAILABLE
        NativeAuthenticationSignFailure.TRANSPORT_ERROR -> AuthenticationSignFailure.TRANSPORT_ERROR
        NativeAuthenticationSignFailure.INVALID_PIN -> AuthenticationSignFailure.INVALID_PIN
        NativeAuthenticationSignFailure.SAFETY_REFUSED -> AuthenticationSignFailure.SAFETY_REFUSED
        NativeAuthenticationSignFailure.PIN_LOCKED -> AuthenticationSignFailure.PIN_LOCKED
        NativeAuthenticationSignFailure.WRONG_PIN -> AuthenticationSignFailure.WRONG_PIN
        NativeAuthenticationSignFailure.VERIFICATION_REJECTED -> AuthenticationSignFailure.VERIFICATION_REJECTED
        NativeAuthenticationSignFailure.SIGNING_REJECTED -> AuthenticationSignFailure.SIGNING_REJECTED
        NativeAuthenticationSignFailure.PACE_REJECTED -> paceRejectedFailure
        NativeAuthenticationSignFailure.BRIDGE_ERROR -> AuthenticationSignFailure.BRIDGE_ERROR
    }

private fun NativeQualifiedSignFailure.toQualifiedFailure(): QualifiedSignFailure =
    when (this) {
        NativeQualifiedSignFailure.CARD_UNAVAILABLE -> QualifiedSignFailure.CARD_UNAVAILABLE
        NativeQualifiedSignFailure.TRANSPORT_ERROR -> QualifiedSignFailure.TRANSPORT_ERROR
        NativeQualifiedSignFailure.INVALID_PIN -> QualifiedSignFailure.INVALID_PIN
        NativeQualifiedSignFailure.SAFETY_REFUSED -> QualifiedSignFailure.SAFETY_REFUSED
        NativeQualifiedSignFailure.PIN_LOCKED -> QualifiedSignFailure.PIN_LOCKED
        NativeQualifiedSignFailure.WRONG_PIN -> QualifiedSignFailure.WRONG_PIN
        NativeQualifiedSignFailure.VERIFICATION_REJECTED -> QualifiedSignFailure.VERIFICATION_REJECTED
        NativeQualifiedSignFailure.CERTIFICATE_REJECTED -> QualifiedSignFailure.CERTIFICATE_REJECTED
        NativeQualifiedSignFailure.INVALID_CERTIFICATE -> QualifiedSignFailure.INVALID_CERTIFICATE
        NativeQualifiedSignFailure.CERTIFICATE_MISMATCH -> QualifiedSignFailure.CERTIFICATE_MISMATCH
        NativeQualifiedSignFailure.KEY_PROFILE_MISMATCH -> QualifiedSignFailure.KEY_PROFILE_MISMATCH
        NativeQualifiedSignFailure.SIGNING_REJECTED -> QualifiedSignFailure.SIGNING_REJECTED
        NativeQualifiedSignFailure.BRIDGE_ERROR -> QualifiedSignFailure.BRIDGE_ERROR
    }
