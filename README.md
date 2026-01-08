# check_ya_self - iOS Runtime environment checks

iOS application exploring Defense In Depth anti tampering and runtime integrity techniques.

We attempt to check integrity of app bundle and the runtime environment.

1. Code Signature
2. Bundle ID  
3. Team ID
4. Entitlements
5. Debugger Detection
6. Jailbreak Detection
7. Dynamic Library Injection Detection
8. Method Swizzling Detection
9. Symbol Binding Tampering
10. Injected Class Detection
11. Suspicious Protocols Detection
12. Environment Variable Checks

Several of the checks herein rely on static lists of known threats. These will age fast.

Given the general inability for an entity to verify it's own state, everything here can be bypassed by a motivated attacker. Also iOS platform limitations prevent more intrusive checks.

---

## Checks

### 1. Code Signature Verification

- Verifies the `_CodeSignature` directory exists in the app bundle
- Checks that Info.plist is readable (basic integrity check)

**Bypass difficulty (guesstimate):** Easy - Only checks basic signature presence

Nb. This check detects obviously tampered apps but motivated attackers would bypass it

---

### 2. Bundle ID Verification

Confirms the app is running with the expected bundle identifier. Attempts to detect repackaging.


- Reads `Bundle.main.bundleIdentifier`
- Compares against hardcoded expected value

**Bypass difficulty (guesstimate):** Easy - can be patched in binary

---

### 3. Team ID Verification

Verifies the Apple Developer Team ID matches expected value.


- Attempts to extract Team ID from embedded.mobileprovision
- Searches for Team ID string in provisioning profile data
- Falls back to true if profile is unavailable (simulator, development)

**Bypass difficulty (guesstimate):** Medium - requires provisioning profile modification

Nb. Only reliable on device

---

### 4. Entitlements Verification

Validates that app entitlements match expected values.


- Parses embedded.mobileprovision for entitlement strings
- Verifies expected entitlements appear in the profile

**Bypass difficulty (guesstimate):** Medium - requires provisioning profile modification

Nb. String-based check, not cryptographic validation

---

### 5. Debugger Detection

Detects if a debugger is attached to the process.


- Uses `sysctl()` to check the `P_TRACED` flag in process info
- Optional: `ptrace(PT_DENY_ATTACH)` to actively block debugger attachment

**Bypass difficulty (guesstimate):** Easy - can be patched or bypassed at kernel level

**Notes:**
- `denyPtraceAttach()` only runs in release builds (`#if !DEBUG`)
- Can interfere with legitimate crash reporting
- Consider using only detection, not prevention, to avoid false positives

---

### 6. Jailbreak Detection

Detects if the device is jailbroken.


Multiple checks:
1. **File existence:** Looks for common jailbreak files (Cydia, Substrate, etc.)
2. **Sandbox escape test:** Tries to write to protected directories
3. **URL scheme check:** Tests if Cydia URL scheme responds
4. ~Fork test: Attempts to fork a process (normally blocked by sandbox)~
5. **Environment variables:** Checks for `DYLD_INSERT_LIBRARIES`

Nb. Is block list, will inevitably become less valuable over time without maintainence. Returns `false` in simulator

---

### 7. Dynamic Library Injection Detection

Detects suspicious or unexpected dynamic libraries loaded into the process.

- Uses `_dyld_image_count()` and `_dyld_get_image_name()` to enumerate loaded libraries
- Checks against list of known hooking frameworks (Frida, Cycript, Substrate, etc.)

**Bypass difficulty (guesstimate):** Easy - attacker can rename libraries or patch the check

Nb. False positives possible if legitimate tools use similar names

---

### 8. Method Swizzling Detection

- Checks common NSObject methods for swizzling
- Verifies implementations are in expected system libraries
- Detects Frida, Cycript, and other hooking frameworks

**Value (guesstimate):** High - reliably detects most Objective-C hooking

---

### 9. Symbol Binding Tampering

- Checks if symbols like ptrace, sysctl, dlopen point to expected libraries
- Detects GOT/PLT hooking and symbol interposition

**Value (guesstimate):** Medium-High - catches symbol-level attacks

---

### 10. Injected Class Detection

- Enumerates all registered Objective-C classes
- Filters out system classes without superclasses (prevents Swift runtime crashes)
- Checks for Frida, Cycript, Substrate, Reveal, Flex, and other tool classes

**Value (guesstimate):** Medium - reliable but susceptible to collisions leading to false positives.

Nb. Includes workaround for Swift runtime crashes when accessing certain system classes (see https://developer.apple.com/forums/thread/767346)

---

### 11. Suspicious Protocols Detection

Detects tweak-related Objective-C protocols

- Enumerates all registered protocols
- Checks for known tweak protocols

**Value (guesstimate):** Medium - useful supplementary check

---

### 12. Environment Variable Checks

Detects injection-related environment variables

- Checks for DYLD_INSERT_LIBRARIES and related variables
- Detects Substrate environment markers

**Value (guesstimate):** High - reliable for detecting dylib injection

---
