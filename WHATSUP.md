# WHATSUP

branch: agent/cargo-outdated
purpose: Update cargo dependencies flagged in audit report cargo-outdated.txt.
started: 2026-09-27T21:57:35+03:00 by antigravity (Antigravity)
heartbeat: 2026-09-27T22:08:50+03:00
status: in-progress

Done:
- Updated cargo dependencies in native/refineid-android-core and native/refineid-rapp-android
  (cfg-if, thiserror, unicode-ident, syn, camino, clap, rustix, siphasher, textwrap, toml, uniffi).
- Regenerated UniFFI Kotlin bindings in refineid-rapp-android.
- Audited with cargo audit and osv-scanner.
- Verified with ./gradlew check and git pre-push gates.
