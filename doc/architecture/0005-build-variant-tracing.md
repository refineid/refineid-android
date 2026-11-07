# ADR 0005: Build-variant tracing

Status: Accepted

Date: 2026-08-15

## Context

Card and browser work crosses process, USB, JNI, and protocol boundaries. A
development build needs enough evidence to distinguish those boundaries, while
a production authentication app must not leave a diagnostic trail.

The Apple implementation already establishes the RefineID policy: development
builds retain all instruments, shipped builds say nothing, and credentials and
personal card data are never trace material.

## Decision

Debug builds provide structured tracing for lifecycle, transport, protocol,
and browser control flow. Product UI remains terse. Card exchange lines may
contain the instruction, an allowlisted non-secret command header, byte counts,
status word, elapsed time, and typed outcome. They never contain response
payloads, certificate or identity data, reader or device identifiers, network
addresses, or credential bytes. VERIFY and other credential commands are
redacted wholesale, including command length and, on the contactless path,
the command header. The CCID frame and bulk-transfer layers below cannot tell
a credential frame from a public one, and an unpadded credential frame is the
credential length plus a fixed header, so they record no outbound byte count:
an exchange line carries the message type, slot, and sequence, and a bulk-out
line only whether the transfer completed, came up short, or failed. Inbound
counts remain, because a card answers a credential command with a status word
whose size does not depend on the credential.

Release builds use a separate empty trace sink. R8 also removes Android Logcat,
console, `java.util.logging`, and Android performance-trace emission from
bundled dependencies, and folds their enablement checks to false. Release
verification parses the optimized DEX method table and rejects every admitted
output method as well as RefineID trace literals and trace classes; a
successful compile is not sufficient evidence.

Call sites pass typed, already-sanitized values to the trace boundary. They do
not format arbitrary card, USB, JNI, exception, or browser objects.

## Consequences

New operational branches need a debug trace event and a redaction decision.
Release builds can still clear local diagnostic state left by a development
build, but cannot create or append to it. A future persistent on-device trace
must be bounded, development-only, and excluded from backup.
