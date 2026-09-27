# WHATSUP

branch: agent/cargo-outdated
purpose: Update cargo dependencies flagged in audit report cargo-outdated.txt.
started: 2026-09-27T21:57:35+03:00 by antigravity (Antigravity)
heartbeat: 2026-09-27T22:18:00+03:00
status: done-pending-merge

Done:
- Updated cargo dependencies in native/refineid-android-core and native/refineid-rapp-android
  (bitflags, camino, cfg-if, clap, clap_builder, clap_derive, clap_lex, rustix, siphasher,
  syn, textwrap, thiserror, thiserror-impl, toml, unicode-ident, unicode-width, uniffi).
- Regenerated UniFFI Kotlin bindings in refineid-rapp-android for UniFFI 0.32.2
  (includes upstream AArch64 u16 checksum mask fix).
- Verified refineid-core path-patch workspace version sync (26.9.27).
- Audited with cargo-audit, osv-scanner, and Scripts/audit-dependencies.sh.
- Verified with ./gradlew check and git pre-push gates.
