#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# Signs an Android App Bundle (.aab) with the developer's hardware identity card
# Qualified Signing Key (PIN 2) via the PKCS#11 provider.
#
# Security: The PIN 2 is never stored or persisted. It is entered interactively
# via terminal prompt, environment variable (PIN2), or hardware reader pinpad.

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

bundle_path="${1:-app/build/outputs/bundle/release/app-release.aab}"

if [[ ! -f "${bundle_path}" ]]; then
  echo "Error: Bundle file not found at ${bundle_path}" >&2
  echo "Run './gradlew bundleRelease' first." >&2
  exit 1
fi

pkcs11_lib="${REFINEID_PKCS11_LIB:-/usr/local/lib/librefineid_pkcs11_sign.dylib}"
if [[ ! -f "${pkcs11_lib}" ]]; then
  if [[ -f "/Library/OpenSC/lib/opensc-pkcs11.so" ]]; then
    pkcs11_lib="/Library/OpenSC/lib/opensc-pkcs11.so"
  elif [[ -f "/usr/local/lib/opensc-pkcs11.so" ]]; then
    pkcs11_lib="/usr/local/lib/opensc-pkcs11.so"
  else
    echo "Error: PKCS#11 module not found at ${pkcs11_lib}" >&2
    echo "Set REFINEID_PKCS11_LIB to the path of your PKCS#11 bridge." >&2
    exit 1
  fi
fi

# Strip any existing signatures so the bundle has a single clean signature
zip -d "${bundle_path}" "META-INF/*.SF" "META-INF/*.RSA" "META-INF/*.DSA" "META-INF/*.EC" "META-INF/MANIFEST.MF" >/dev/null 2>&1 || true

pkcs11_cfg="$(mktemp /tmp/refineid_bundle_pkcs11.XXXXXX.cfg)"
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
  echo "Error: No signing key found on the hardware card." >&2
  exit 1
fi

echo "Signing ${bundle_path} with alias: ${alias_name}..."

# Prompt securely for PIN 2 if not provided via environment variable
if [[ -n "${PIN2:-}" ]]; then
  _PASS="${PIN2}"
elif [[ -t 0 ]]; then
  read -s -r -p "Enter Identity Card PIN 2 (Qualified Signature): " user_pin
  echo ""
  _PASS="${user_pin}"
else
  _PASS=""
fi

export _TEMP_PIN_PASS="${_PASS}"

jarsigner_cmd=(
  "${JAVA_HOME}/bin/jarsigner"
  -keystore NONE
  -storetype PKCS11
  -providerClass sun.security.pkcs11.SunPKCS11
  -providerArg "${pkcs11_cfg}"
)

if [[ -f "upload_cert_chain.pem" ]]; then
  jarsigner_cmd+=(-certchain upload_cert_chain.pem)
fi

if [[ -n "${_TEMP_PIN_PASS}" ]]; then
  jarsigner_cmd+=(-storepass:env _TEMP_PIN_PASS)
else
  jarsigner_cmd+=(-protected)
fi

"${jarsigner_cmd[@]}" "${bundle_path}" "${alias_name}"

unset _TEMP_PIN_PASS

echo "Verifying bundle signature..."
"${JAVA_HOME}/bin/jarsigner" -verify "${bundle_path}"

echo "Android App Bundle successfully signed with hardware identity card."
