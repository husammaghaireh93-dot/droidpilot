# Slice 1 Verification & Security Test Plan

## 1. Strict Preconditions (Mandatory Before Any On-Device Test)
1. **Wireless Debugging (`ADB` over Wi-Fi) MUST be OFF** in Developer Options.
2. **Shizuku MUST NOT be installed or running** on the device.
   *(Reason: With ADB or Shizuku enabled, any shell in Termux can click notification buttons or inject input events, bypassing notification-based human consent.)*
3. **Debug APK Only**: Built exclusively via GitHub Actions CI (`assembleDebug`) with SHA-256 verified against the CI job summary before installation.
4. **Target App Scope (Slice 1)**: Calculator only (`com.google.android.calculator` / `com.android.calculator2`).

---

## 2. Automated Pure-JVM Unit Tests (Run in CI via `testDebugUnitTest`)
Executed via `./gradlew testDebugUnitTest` inside `android/`:
- `SecurityPolicyTest`:
  - Verifies every command in `PolicyEngine.ALL_KNOWN_COMMANDS` (18 commands total): allows `get_ui_tree`, gates `click_element` and `type_text` (`REQUIRE_CONSENT`), and denies all other 15 commands (`tap`, `long_press`, `swipe`, `set_text`, `press_key`, `find_element`, `screenshot`, `wait_for_element`, `open_app`, `get_device_info`, `scroll`, `pinch`, `get_focused`, `notifications`, `ping`).
  - Verifies package whitelist on both read (`get_ui_tree`) and mutation commands, plus `verifyTargetNodePackage(..., refreshed = false)` denial.
  - Verifies `WebSocketCommandServer` rejects empty/invalid tokens in constant time and rejects non-loopback `InetAddress`.
  - Verifies `NodeSanitizer` strips `text` and `contentDescription` whenever `isPassword == true`.
  - Verifies `ConsentCoordinator` (injectable fake clock): notification prerequisite, concurrency limit = 1, forged nonce rejection, single-use nonce enforcement, and timeout default-deny.
  - Verifies `AuditLogger` SHA-256 hash chain across restarts and detects middle-line modification or deletion.

---

## 3. Manual Slice 1 Functional & Adversarial Security Tests

### T1: Loopback & Token Authentication
- Attempt WebSocket connection from another device on LAN -> Rejected (`127.0.0.1` bind + `isLoopbackRemote` check).
- Attempt local Termux WebSocket connection without `Authorization: Bearer <token>` or with wrong token -> Closed with `4001 Unauthorized`.
- Tap `[Tap to Copy Token Safely]` in `MainActivity` -> Token never rendered visibly on screen; copied with `ClipDescription.EXTRA_IS_SENSITIVE` on Android 13+; `connect` succeeds without calling `ping` or `get_device_info`.

### T2: Allowed Read (`get_ui_tree`) in Calculator vs Other Apps
- Open Android Settings (`com.android.settings`), invoke `get_ui_tree` -> Denied (`Package 'com.android.settings' is not in the allowed package whitelist.`).
- Open Calculator (`com.google.android.calculator` or `com.android.calculator2`), invoke `get_ui_tree` -> Succeeds, returns UI tree without prompt.

### T3: Approved Mutation (`click_element` / `type_text`) + Post-Consent Re-Verification
- With Calculator in foreground, invoke `click_element` on digit `7` -> High-priority notification appears with `Approve` / `Deny`.
- Tap `Approve` -> Digit `7` is clicked in Calculator; `audit_chain.jsonl` records `approved` / `executed`.
- **Overlay / App-Switch Race Check**: Request `click_element` while Calculator is foreground, switch to Settings before tapping `Approve` -> Post-consent `rootInActiveWindow` + `refresh()` + `target.packageName` check detects package change and denies execution.

### T4: Consent Timeout -> Default-Deny
- Request `click_element` while Calculator is foreground.
- Do **not** tap `Approve` or `Deny` for >15 seconds (`ConsentCoordinator.DEFAULT_TIMEOUT_MS`).
- **Expected**: Notification cancels automatically, WebSocket returns error `"User denied or consent timed out (default-deny)."`, action is NOT executed, and audit log records `denied_or_timeout`.

### T5: `POST_NOTIFICATIONS` Permission Denied -> Immediate Deny
- Revoke Notification permission for DroidPilot in Android App Settings (Android 13+).
- Request `click_element` while Calculator is foreground.
- **Expected**: `areNotificationsEnabled()` returns `false`, `ConsentCoordinator.startConsent(false)` denies immediately, no action is executed, and audit log records `"Notifications are disabled; cannot gather explicit user consent."`.

### T6: Direct Broadcast Spoofing from Termux (`am broadcast -n`)
- From Termux shell while a consent prompt is pending (or idle), attempt:
  ```bash
  am broadcast -n com.mobilemcp.pro/.service.ConsentReceiver \
    -a com.mobilemcp.pro.ACTION_CONSENT_DECISION \
    --es extra_nonce "00000000000000000000000000000000" \
    --ez extra_approved true
  ```
- **Expected**: Rejected by Android OS with `java.lang.SecurityException: Permission Denial` because `ConsentReceiver` has `android:exported="false"`. Even if an unguessable 128-bit nonce existed internally, unknown/replayed nonces are rejected by `ConsentCoordinator.submitDecision`.

### T7: Gesture Injection Attempt Over Consent Notification (`swipe` / `tap`)
- While a consent notification is displayed at the top of the screen, send `swipe` (or `tap` / `long_press`) from the agent to drag/tap the `Approve` action button coordinates.
- **Expected**: Immediately denied at `PolicyEngine.evaluate` (`Command 'swipe' is denied by default-deny allowlist.`), and `accessibility_service_config.xml` also sets `android:canPerformGestures="false"`. Zero gestures can be dispatched.
