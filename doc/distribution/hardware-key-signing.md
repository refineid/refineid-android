# Hardware Identity Card Signing & Google Cloud HSM Distribution

Status: Active

Date: 2026-08-31

## Architecture

RefineID releases are secured by combining developer hardware identity card signatures with Google Play Cloud HSM protection:

```
[ Physical Identity Card (PIN 2 Qualified Key) ]
                        │
                        ▼ (PKCS#11 / SunPKCS11)
          [ Signed App Bundle (.aab) ]
                        │
                        ▼ (Upload to Google Play)
      [ Validated against Upload Certificate ]
                        │
                        ▼
       [ Google Cloud HSM / Play App Signing ] ──► [ Signs final per-device APKs ]
```

### 1. Developer Upload Key (Hardware ID Card PIN 2)
- The developer's physical identity card with **PIN 2 (Qualified Signature Key)** is used to sign release bundles (`.aab`) prior to upload.
- Google Play validates every incoming release against the registered public **Upload Certificate**.
- **PIN Security:** PIN 2 is never stored, committed, or hardcoded anywhere in the codebase. It is entered interactively or processed directly by the smartcard reader.

### 2. Google Cloud HSM (Play App Signing)
- Google Play App Signing holds the root App Signing Key in **Google Cloud Key Management Service (Cloud HSM)** backed by FIPS 140-2 Level 3 Hardware Security Modules.
- Google verifies the developer's upload signature, removes the upload wrapper, and signs device-specific delivery APKs using the Cloud HSM key.

---

## Workflow Guide

### Step 1: Export Upload Certificate from Identity Card
Export the public certificate from your card once to register in Play Console:

```bash
./Scripts/export-upload-certificate.sh upload_cert.pem
```

### Step 2: Register in Google Play Console
1. Open **Google Play Console** -> **Setup** -> **App Integrity** -> **Play App Signing**.
2. Select **Use Google Play App Signing**.
3. Upload `upload_cert.pem` as your **Upload Key Certificate**.

### Step 3: Build and Sign Releases
Build the compliant release bundle:
```bash
./gradlew check bundleRelease
```

Sign the bundle using your hardware identity card:
```bash
./Scripts/sign-release-bundle.sh
```

### Step 4: Replacing / Rotating the Identity Card Key
When your hardware identity card is renewed or replaced:
1. Export the new public certificate: `./Scripts/export-upload-certificate.sh new_upload_cert.pem`
2. In Google Play Console, go to **App integrity** -> **App signing**.
3. Click **Request upload key reset** and upload `new_upload_cert.pem`.
4. Google verifies and activates the new upload key.
