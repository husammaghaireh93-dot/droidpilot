# DroidPilot Hardening Verification & Security Test Plan (Slice 1 + Slice 2 + Slice 3)

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

---

## 4. Slice 2 Automated & On-Device Scenarios (Tiered Package Model + Consent Rate Limiter)

### Automated JVM Tests Added in `SecurityPolicyTest`
- **`TIER_0_HARD_DENY` (Non-Overridable)**:
  - Permanently blocks financial/banking/wallet apps (`com.reflect`, `com.umniah.uwallet`, and keyword matches like `*bank*`, `*wallet*`, `*fintech*`, `*payment*`, `*crypto*`, `*pay*`), system settings (`com.android.settings`), password managers/authenticators (`com.x8bit.bitwarden`, `com.agilebits.onepassword`, `com.lastpass.lpandroid`, `com.google.android.apps.authenticator2`), package installers (`com.android.packageinstaller`, `com.google.android.packageinstaller`), and self-protection (`com.mobilemcp.pro`).
  - Verified non-overridable even if passed explicitly to `PolicyEngine(readOnlyPackages = ..., consentGatedPackages = ...)`.
- **`TIER_1_READ_ONLY`**:
  - Permits `get_ui_tree` (with `NodeSanitizer` redacting `isPassword` fields) on read-only packages (`com.google.android.deskclock`, `com.google.android.calendar`, etc.).
  - Strictly denies `click_element` and `type_text` at `evaluate`, `verifyTargetNodePackage`, and `verifyPostConsentContext`.
- **`TIER_2_CONSENT_GATED`**:
  - Covers Calculator variants (`com.google.android.calculator`, `com.android.calculator2`, `com.hihonor.calculator`, `com.huawei.calculator`) and explicitly approved non-financial apps.
  - Requires per-action consent and strict `verifyPostConsentContext` match.
- **`ConsentRateLimiter`**:
  - Enforces max 5 consent prompts per 60s sliding window; 6th request is denied with `rateLimited = true` until the oldest timestamp ages out (>= 60s).
  - Enforces mandatory 60s cooldown after 3 consecutive denials/timeouts, logs `cooldown_activated_60s` into `AuditLogger` with valid SHA-256 chain integrity, resets failure streak upon approval, and recovers cleanly once the 60s cooldown expires.

### Manual Slice 2 Verification Scenarios
- **T8 (`TIER_0_HARD_DENY` Financial & Settings)**: Open `com.reflect`, `com.umniah.uwallet`, or `com.android.settings` -> `get_ui_tree`, `click_element`, and `type_text` are all immediately denied (`TIER_0_HARD_DENY`).
- **T9 (`TIER_1_READ_ONLY` Clock / Calendar)**: Open Clock (`com.google.android.deskclock` / `com.hihonor.deskclock`) -> `get_ui_tree` succeeds with `NodeSanitizer`; `click_element` and `type_text` are immediately denied without showing a consent prompt.
- **T10 (`ConsentRateLimiter` Flood & Cooldown)**: Trigger 3 consecutive consent denials/timeouts in Calculator -> 4th `click_element` immediately returns cooldown error without prompting; `audit_chain.jsonl` records `cooldown_activated_60s`; after 60s, prompts resume normally. Trigger 5 rapid prompts within 1 minute -> 6th prompt is rate-limited until the sliding window advances.

---

## 5. Slice 3 Automated & Manual Scenarios (Dynamic Policy Store, Audit Bundle Export & Release Hardening)

### Automated JVM Tests Added in `SecurityPolicyTest`
- **`DynamicPolicyStore` Encryption & Live Enforcement**:
  - Persists dynamic `TIER_1_READ_ONLY` and `TIER_2_CONSENT_GATED` assignments via AES/GCM/NoPadding (`InMemoryEncryptedPolicyVault` in JVM tests, `AndroidKeystorePolicyVault` on Android).
  - Applies updates immediately in `PolicyEngine` without restarting `MobileAccessibilityService` and restores them cleanly on reload.
  - Rejects any attempt to add `TIER_0_HARD_DENY` packages (including `com.reflect`, `com.umniah.uwallet`, `com.android.settings`, `com.x8bit.bitwarden`, `com.android.packageinstaller`, `com.mobilemcp.pro`) and strips them even if storage payload is tampered.
- **`AuditLogger` Bundle Export & Independent Verifier**:
  - `exportSignedAuditBundle` outputs JSON containing `entries` (`prevHash` / `hash`), top-level & `summary` metadata (`chainValid`, `entryCount`, `firstHash`, `lastHash`, `exportedAtEpochMs`), and `bundleDigestSha256`.
  - `verifyExportedBundle` / `verifyExportedBundleDetailed` validates untampered bundles and rejects any status modification, metadata/timestamp edit, or entry deletion.
- **Release R8/ProGuard Build Verification (CI)**:
  - CI runs `./gradlew assembleRelease` with `isMinifyEnabled = true` and `isShrinkResources = true` against `proguard-rules.pro`.

### Manual Slice 3 Verification Scenarios (`T11–T14`)
- **T11 (Immediate Auth Token Rotation via UI)**:
  - Connect a WebSocket client using the active token.
  - Tap **`Rotate Auth Token`** in `MainActivity` -> active WebSocket disconnects immediately with close code `4001` (`Unauthorized: Auth token rotated`), token is never rendered/logged in plaintext, and reconnecting with the old token fails with `4001`.
- **T12 (Dynamic Policy Management & `TIER_0_HARD_DENY` Guard)**:
  - Enter `com.reflect` or `com.android.settings` in the Dynamic Package Tiers field and tap **`Add TIER_1 (Read-Only)`** or **`Add TIER_2 (Consent)`** -> immediately rejected with `TIER_0_HARD_DENY` error message.
  - Enter an allowed non-financial package (e.g. `com.example.notes`), tap **`Add TIER_2 (Consent)`**, and verify it is enforced live without restarting Accessibility Service, then tap **`Remove Package`** to revert to default-deny.
- **T13 (Tamper-Evident Audit Bundle Export via SAF)**:
  - Tap **`Export Audit Log (JSON)`** -> Android Storage Access Framework (`ACTION_CREATE_DOCUMENT`) saves `droidpilot-audit-bundle.json` without external storage permissions.
  - Verify `chainValid: true` and `entryCount` matches; modify one character in the exported file and confirm `AuditLogger.verifyExportedBundle` rejects it.
- **T14 (Production Release Build Verification)**:
  - Confirm GitHub Actions CI passes `testDebugUnitTest`, `assembleDebug`, and `assembleRelease` (R8 minification + resource shrinking) and verifies SHA-256 checksums for both artifacts.
