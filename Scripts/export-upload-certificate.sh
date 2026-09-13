#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# Exports the public X.509 certificate for PIN 2 (Qualified Signature) from the
# developer's hardware identity card via SunPKCS11 for Google Play upload key registration.

set -euo pipefail
cd "$(dirname "$0")/.."

# Set JAVA_HOME if not already set.
if [[ -z "${JAVA_HOME:-}" ]] && [[ "$(uname)" == "Darwin" ]]; then
  studio_jdk="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
  if [[ -d "${studio_jdk}" ]]; then
    export JAVA_HOME="${studio_jdk}"
  else
    export JAVA_HOME="$(/usr/libexec/java_home 2>/dev/null || echo "/opt/homebrew/opt/openjdk")"
  fi
fi

output_cert="${1:-upload_cert.pem}"
pkcs11_lib="${REFINEID_PKCS11_LIB:-/usr/local/lib/librefineid_pkcs11_sign.dylib}"

if [[ ! -f "${pkcs11_lib}" ]]; then
  if [[ -f "/Library/OpenSC/lib/opensc-pkcs11.so" ]]; then
    pkcs11_lib="/Library/OpenSC/lib/opensc-pkcs11.so"
  elif [[ -f "/usr/local/lib/opensc-pkcs11.so" ]]; then
    pkcs11_lib="/usr/local/lib/opensc-pkcs11.so"
  else
    echo "Error: PKCS#11 module not found at ${pkcs11_lib}" >&2
    exit 1
  fi
fi

pkcs11_cfg="$(mktemp /tmp/pkcs11_export.XXXXXX.cfg)"
trap 'rm -f "${pkcs11_cfg}"' EXIT
cat << EOF > "${pkcs11_cfg}"
name = RefineIDSign
library = ${pkcs11_lib}
slotListIndex = 0
EOF

echo "Discovering alias from hardware identity card..."
alias_name=$("${JAVA_HOME}/bin/keytool" \
  -keystore NONE \
  -storetype PKCS11 \
  -providerClass sun.security.pkcs11.SunPKCS11 \
  -providerArg "${pkcs11_cfg}" \
  -protected \
  -list 2>/dev/null | grep -E "PrivateKeyEntry|trustedCertEntry" | cut -d',' -f1 || true)

if [[ -z "${alias_name}" ]]; then
  echo "Error: No signing key or certificate found on the hardware card." >&2
  exit 1
fi

echo "Exporting public certificate for: ${alias_name}"
"${JAVA_HOME}/bin/keytool" \
  -keystore NONE \
  -storetype PKCS11 \
  -providerClass sun.security.pkcs11.SunPKCS11 \
  -providerArg "${pkcs11_cfg}" \
  -protected \
  -exportcert \
  -rfc \
  -alias "${alias_name}" \
  -file "${output_cert}"

echo "Public upload certificate exported to ${output_cert}"
echo ""
echo "Certificate details:"
openssl x509 -in "${output_cert}" -noout -subject -issuer -dates -fingerprint -sha256
