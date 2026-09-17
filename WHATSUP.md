# WHATSUP

branch: agent/signing-lifecycle
purpose: Fix signing document-selection lifecycle bug: picker results lost when USB refresh on activity return drops the signing composable.
started: 2026-09-17T00:44+0300 by rain-daphnis (Muse Code)
heartbeat: 2026-09-17T05:05+0300
status: done-pending-merge

Done:
- Session/scopes/pickers live for the whole signing visit; sign refused
  visibly while unavailable (UNAVAILABLE); transport latched per visit;
  healthy USB sessions kept across foreground refresh.
- Regression cover: lifecycle compose 7/7, card 9/9, MainScreen 8/8,
  unit latch 9/9 + policy 8/8, MainActivity UI test green, live picker
  round trip green (USB kept=healthy-session observed twice live).
- Live entry test rewritten: synthetic MediaStore PDF, real system
  picker select + cancel, startup-dialog dismissal with USB-grant retry.
- MainActivity test fixed: current home surface (mainScreen + verifyRow)
  plus startup-dialog dismissal (was asserting removed reader cards).
- Gates: ./gradlew check exit 0, verify-commit exit 0, audits clean.
- Note: connectedDebugAndroidTest exits 1 even for all-pass suites in
  this environment (untouched MainScreen 8/8 control shows the same);
  XML verdicts are authoritative.
