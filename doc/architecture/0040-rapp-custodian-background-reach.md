# ADR 0040: RAPP custodian background reach

## Status

Accepted.

## Context

As a RAPP custodian, the phone answers requests from paired computers. A
browser login or a document signature starts on the computer, usually while
RefineID is not on the phone's screen. The holder must not have to open
RefineID before a request can reach the phone.

Stock Android works against an app without a visible activity in three ways.
The protocol does not create any of them:

- A process with no activity or service becomes cached. The cached-app
  freezer suspends it after a short debounce, so its listening socket stops
  answering even though the process still exists. Later the process may be
  killed outright.
- Android 10 and newer block activity starts from the background. RefineID
  cannot raise its own consent screen from a network event.
- On Android 13 and newer, notifications need the runtime `POST_NOTIFICATIONS`
  permission. Without it, posted notifications are silently discarded. On
  Android 14 and newer, full-screen intents need the special
  `USE_FULL_SCREEN_INTENT` access, which Google Play grants by default only to
  calling and alarm apps. The holder can grant it in system settings.

A USB card reader does not change any of this. The phone never needs the card
held against it unless the card is on the contactless interface.

## Decision

- **Reachability.** While the session listener is open (Remote Access on and
  at least one custodian pairing), `RappCustodianService` runs as a
  `connectedDevice` foreground service. The process stays in the
  foreground-service state with network access, the listener keeps answering,
  and the platform shows an ongoing, silent "Remote Access" notification on a
  low-importance channel. The service starts and stops with the listener in
  `RappPhoneProxyDispatcher`. It holds no protocol state.
- **Restart.** `RappCustodianRestartReceiver` handles `BOOT_COMPLETED` and
  `MY_PACKAGE_REPLACED`, so the listener and service return after a reboot or
  an update without the holder opening the app. If the platform refuses a
  start from the background, the next activity start retries it.
- **Requests.** A request that arrives with no RefineID activity resumed posts
  a high-importance notification. Its text names the requester and the action
  (login, one signature, or a batch count), never the card interface. Tapping
  it opens the consent dialog for that request. When
  `NotificationManagerCompat.canUseFullScreenIntent()` holds, the notification
  also carries a full-screen intent, so a sleeping screen wakes for it. The
  consent activity does not show over the keyguard: on a locked phone the
  holder unlocks first, because PIN 1 may be cached and an approval must come
  from the device owner.
- **Permissions.** RefineID asks for `POST_NOTIFICATIONS` when Remote Access
  is on with a pairing, and again when the holder turns Remote Access on. While
  notifications or full-screen access are off, the Remote Access screen offers
  one row that opens the matching system settings page.
- **Card wait.** The card prompt during a remote operation follows the
  available reader. With a USB reader attached it asks the holder to insert the
  card. Otherwise it asks the holder to hold the card against the phone.

## Verification

Observed on a stock Android 16 phone with a debug build:

- After `adb install -r`, with no activity started, the process returned
  through `MY_PACKAGE_REPLACED`. `dumpsys activity services` showed
  `RappCustodianService` with `isForeground=true` and type `connectedDevice`.
  The process held `procState` 4 (foreground service) and was not frozen 30
  seconds later.
- A Mac on the same network browsed `_refineid-stream._tcp` and found the
  phone's session instance while no RefineID activity had been started.

Not yet observed: delivery after a reboot, and the full-screen intent on a
locked phone.

## Consequences

Remote Access keeps an ongoing notification visible while it is on. This is
the platform's price for a reachable background listener, and it tells the
holder that the phone answers paired computers. Turning Remote Access off, or
removing the last pairing, stops the service and removes the notification.

A Google Play release must declare the `connectedDevice` foreground-service
use. Play reviews full-screen intent use: without the default grant, the
request still arrives as a heads-up notification.
