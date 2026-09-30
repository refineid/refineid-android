# Security Policy

**Open a public issue.** Full technical detail is expected and wanted, including
the attack path, the reachable code, and why the control that should prevent it
does not. A fix needs the mechanism, not a summary. A public record also means
the next reviewer can see what was considered, what was rejected, and why,
instead of rediscovering it.

Report what is broken, with `file:line`, the quoted code, and a concrete
scenario. Do not soften the finding and do not file it as a question. Label it
`security` plus the severity you judge, and say plainly what you could not
establish.

There is no embargo and no private channel. RefineID is pre-release and
single-maintainer; coordinated disclosure buys nothing that a public issue does
not, and the delay costs the project the other fixes in the queue.

## Never in a report, public or otherwise

A PIN, PUK, CAN, candidate PIN length, private key, full personal certificate,
personal identity code, or unredacted event log. Those values identify a real
person, and nothing published on the internet can be unpublished.

Sanitized status words, APDU shapes, and structural descriptions carry all the
information a fix needs.

## Supported Versions

Latest

## Inviolable rules

Rule #1: PIN codes never travel over the network. PIN1 and PIN2 never leave the
phone when accessed via RAPP; PIN1 is cached on-device; PIN2 prompts appear only
on the phone; the host operates via a protected authentication path and never
prompts for or transports a PIN.

Rule #2: Zero PIN and PIN-length logging across all environments. Never log,
trace, display, or format PIN bytes, candidate PIN lengths, or development PIN
role identifiers in log sinks, audit records, test attachments, or error
strings.
