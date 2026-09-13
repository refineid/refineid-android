# ADR 0040: CCID interrupt-driven events and slot protocol negotiation

Status: Accepted

Date: 2026-09-12

## Context

Android lacks a native operating system PC/SC daemon or smart-card slot manager.
All USB CCID reader interactions are managed directly by the application layer
over Android USB Host (`android.hardware.usb`).

Three hardware interoperability and latency challenges were identified across physical
readers:

1. **Card Removal Latency:**
   Previous card removal detection was coupled to active APDU transmission failures
   or periodic timer polling. When an identity card was physically removed from a
   connected reader, the application did not update immediately, leaving stale card
   and certificate state in the UI.

2. **Dual-Interface Reader Negotiation (ACS ACR1581U-CF):**
   Finnish Citizen Certificate cards (FINEID) return an Answer-to-Reset (ATR)
   indicating support for both T=0 and T=1 in negotiable mode without a `TA2` specific
   mode byte (`TD1 = 0x80`, `TD2 = 0x31`). Dual-interface APDU-level readers such as the
   ACS ACR1581U-CF (`dwFeatures = 0x404BA`, indicating `AUTO_PPS_CUR` / bit 7) default
   their slot protocol to T=1 when activating a multi-protocol card if no explicit
   parameter configuration is provided. Because the card boots into T=0 mode awaiting
   commands, transmitting T=1 frames resulted in a 1-second timeout and an `ICC_MUTE` (-2)
   failure.

3. **Descriptor Whitelist Over-constraint (HID OMNIKEY 3021):**
   The CCID functional descriptor parser previously mandated bit 1
   (`AUTOMATIC_PARAMETER_CONFIGURATION`, `0x02`) of `dwFeatures`. Standard CCID readers
   such as the HID OMNIKEY 3021 (`dwFeatures = 0x407B8`) omit bit 1 while fully supporting
   automatic PPS and APDU exchange, resulting in rejection with `INVALID_APDU_CONFIGURATION`.

## Decision

### 1. Interrupt-IN Event Monitoring

Per USB-IF CCID Specification Revision 1.1 Section 6.3, readers provide an Interrupt-IN
endpoint delivering slot change notifications (`RDR_to_PC_NotifySlotChange`, `0x50`) and
hardware error notifications (`RDR_to_PC_HardwareError`, `0x51`).

`CcidUsbSession` spawns a dedicated daemon thread (`refineid-ccid-interrupt`) when a
session is established. The thread performs synchronous USB bulk transfers against the
Interrupt-IN endpoint:

- On `RDR_to_PC_NotifySlotChange`, the slot state byte is inspected. If bit 0 indicates
  the card is absent (`(slotIccState & 0x01) == 0`), `cardRemoved` is marked and an
  instant removal callback dispatches to `UsbReaderController`.
- The controller tears down the active card session and immediately updates the
  repository snapshot (`status = READY, card = ABSENT`), eliminating polling delay.

### 2. Explicit Slot Protocol Configuration (`PC_to_RDR_SetParameters`)

`CcidCodec` is extended with:
- `PC_to_RDR_GetParameters` (`0x6C`)
- `PC_to_RDR_SetParameters` (`0x61`) for T=0 (`ProtocolDataStructureT0`)
- `RDR_to_PC_Parameters` (`0x82`) response parsing

In `CcidCardActivator`, when an APDU-level reader (`dwFeatures` bit 18 `SHORT_AND_EXTENDED_APDU`)
features `AUTO_PPS_CUR` (bit 7) and activates a card whose ATR resolves to T=0,
it performs an explicit `PC_to_RDR_SetParameters` command setting protocol 0 (T=0)
with standard transmission parameters (`FiDi = 0x11`) prior to sending APDUs.

This resolves the ACR1581 `ICC_MUTE` failure and guarantees the reader slot and card
operate on the same transmission protocol.

### 3. CCID Descriptor Acceptance

`CcidFunctionalDescriptor` relaxes the `dwFeatures` validation rule to permit APDU-level
readers that support automatic activation and PPS without strictly requiring bit 1
(`AUTOMATIC_PARAMETER_CONFIGURATION`). This admits standard readers including the HID
OMNIKEY 3021.

### 4. Recovery on Transient Transport Errors

`UsbReaderController` permits `ReaderConnectionStatus.TRANSPORT_ERROR` in `shouldPoll`,
enabling automatic reconnection attempts if a reader interface briefly desynchronizes
or encounters an initial probe failure.

## Cross-Platform Alignment

This behavior matches findings on other RefineID platforms:

- **Apple (`refineid-apple`):** In `SmartCardProtocolNegotiation.swift`, CryptoTokenKit
  offers `[.any, .t0, .t1]` because readers botch multi-protocol negotiation when
  offered `.any` alone.
- **Unix (`refineid-unix`):** In `refineid-lib-pcsc`, `connect_resilient` tries
  `[Protocols::ANY, Protocols::T0, Protocols::T1]` to recover from `pcsc::Error::UnresponsiveCard`.
- **Core and Windows (`refineid-core`, `refineid-windows`):** Should adopt the same
  resilient protocol fallback on PC/SC connect to guard against multi-protocol ATR
  negotiation failures in direct PC/SC environments.
