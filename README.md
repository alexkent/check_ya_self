# check_ya_self - iOS Security Implementation

iOS application exploring defense-in-depth anti-tampering and runtime integrity techniques.

Detects most common iOS tampering techniques, using public APIs.

## Overview

**'Basic' Security Checks:**
1. Code Signature Verification
2. Bundle ID Verification  
3. Team ID Verification
4. Entitlements Verification
5. Debugger Detection
6. Jailbreak Detection (5 methods)
7. Dynamic Library Injection Detection
8. Method Swizzling Detection
9. Symbol Binding Tampering
10. Injected Class Detection
11. Suspicious Protocols Detection
12. Environment Variable Checks

Several of the checks herein rely on static lists of known threats. These will age fast.

Regularly review jailbreak detection paths, test with new OS versions, jailbreak releases, security incidents.

## Limitations

**Important:** client-side security can be bypassed by a determined attacker with enough time and resources. These checks attempt to raise the bar but don't make attacks impossible.

These techniques are not available on iOS due to platform restrictions:
- Kernel-level checks
- Cryptographic signature validation
- Memory protection inspection
- System call monitoring

---

## Implemented Checks

### 1. Code Signature Verification

**What it does:** Verifies that the app's has a code signature.

**How it works:**
- Verifies the `_CodeSignature` directory exists in the app bundle
- Checks that Info.plist is readable (basic integrity check)

**Implementation:** `SecurityManager.checkCodeSignature()`

**Bypass difficulty:** Easy - Only checks basic signature presence

**Notes:**
- On iOS, full signature validation requires private APIs or MachO parsing
- This check detects obviously tampered apps but motivated attackers would bypass it
- Combine with other techniques for better coverage

---

### 2. Bundle ID Verification

**What it does:** Confirms the app is running with the expected bundle identifier.

**How it works:**
- Reads `Bundle.main.bundleIdentifier`
- Compares against hardcoded expected value

**Implementation:** `SecurityManager.checkBundleID()`

**Bypass difficulty:** Easy - can be patched in binary

**Notes:**
- Simple but effective against basic repackaging

---

### 3. Team ID Verification

**What it does:** Verifies the Apple Developer Team ID matches expected value.

**How it works:**
- Attempts to extract Team ID from embedded.mobileprovision
- Searches for Team ID string in provisioning profile data
- Falls back to true if profile is unavailable (simulator, development)

**Implementation:** `SecurityManager.checkTeamID()`

**Bypass difficulty:** Medium - requires provisioning profile modification

**Notes:**
- Only reliable on device

---

### 4. Entitlements Verification

**What it does:** Validates that app entitlements match expected values.

**How it works:**
- Parses embedded.mobileprovision for entitlement strings
- Verifies expected entitlements appear in the profile

**Implementation:** `SecurityManager.checkEntitlements()`

**Bypass difficulty:** Medium - requires provisioning profile modification

**Notes:**
- Customize `ExpectedValues.requiredEntitlements` for your app
- This is a string-based check, not cryptographic validation

---

### 5. Debugger Detection

**What it does:** Detects if a debugger is attached to the process.

**How it works:**
- Uses `sysctl()` to check the `P_TRACED` flag in process info
- Optional: `ptrace(PT_DENY_ATTACH)` to actively block debugger attachment

**Implementation:** 
- Detection: `SecurityManager.isDebuggerAttached()`
- Prevention: `SecurityManager.denyPtraceAttach()`

**Bypass difficulty:** Easy - can be patched or bypassed at kernel level

**Notes:**
- `denyPtraceAttach()` only runs in release builds (`#if !DEBUG`)
- Can interfere with legitimate crash reporting - test thoroughly
- Many attackers can bypass this, but it raises the bar
- Consider using only detection, not prevention, to avoid false positives

---

### 6. Jailbreak Detection

**What it does:** Detects if the device is jailbroken.

**How it works:**
Multiple checks:
1. **File existence:** Looks for common jailbreak files (Cydia, Substrate, etc.)
2. **Sandbox escape test:** Tries to write to protected directories
3. **URL scheme check:** Tests if Cydia URL scheme responds
4. ~Fork test: Attempts to fork a process (normally blocked by sandbox)~
5. **Environment variables:** Checks for `DYLD_INSERT_LIBRARIES`

**Implementation:** `SecurityManager.isJailbroken()`

**Bypass difficulty:** Medium - motivated attackers can bypass all checks

**Notes:**
- Always returns `false` in simulator
- Only checks static list of known jailbreaks

---

### 7. Dynamic Library Injection Detection

**What it does:** Detects suspicious or unexpected dynamic libraries loaded into the process.

**How it works:**
- Uses `_dyld_image_count()` and `_dyld_get_image_name()` to enumerate loaded libraries
- Checks against list of known hooking frameworks (Frida, Cycript, Substrate, etc.)

**Implementation:** 
- Detection: `SecurityManager.checkForSuspiciousLibraries()`
- Inspection: `SecurityManager.getLoadedLibraries()`

**Bypass difficulty:** Easy - attacker can rename libraries or patch the check

**Notes:**
- Useful for detecting common instrumentation frameworks
- False positives possible if legitimate tools use similar names
- Can be extended to maintain a whitelist of expected libraries


---

## Advanced Runtime Integrity Checks

Beyond the 7 basic checks above, the app includes 5 additional advanced checks via `RuntimeIntegrityChecker`:

### 8. Method Swizzling Detection

**What it does:** Detects if Objective-C methods have been hooked/swizzled

**How it works:**
- Checks common NSObject methods for swizzling
- Verifies implementations are in expected system libraries
- Detects Frida, Cycript, and other hooking frameworks

**Implementation:** `RuntimeIntegrityChecker.detectCommonSwizzling()`

**Effectiveness:** High - reliably detects most Objective-C hooking

---

### 9. Symbol Binding Tampering

**What it does:** Detects if critical symbols have been rebound

**How it works:**
- Checks if symbols like ptrace, sysctl, dlopen point to expected libraries
- Detects GOT/PLT hooking and symbol interposition

**Implementation:** `RuntimeIntegrityChecker.checkSymbolBinding()`

**Effectiveness:** Medium-High - catches symbol-level attacks

---

### 10. Injected Class Detection

**What it does:** Detects suspicious Objective-C classes at runtime

**How it works:**
- Enumerates all registered Objective-C classes
- Filters out system classes without superclasses (prevents Swift runtime crashes)
- Checks for Frida, Cycript, Substrate, Reveal, Flex, and other tool classes

**Implementation:** `RuntimeIntegrityChecker.detectInjectedClasses()`

**Effectiveness:** High - very reliable detection

**Note:** Includes workaround for Swift runtime crashes when accessing certain system classes (see https://developer.apple.com/forums/thread/767346)

---

### 11. Suspicious Protocols Detection

**What it does:** Detects tweak-related Objective-C protocols

**How it works:**
- Enumerates all registered protocols
- Checks for known tweak protocols

**Implementation:** `RuntimeIntegrityChecker.detectSuspiciousProtocols()`

**Effectiveness:** Medium - useful supplementary check

---

### 12. Environment Variable Checks

**What it does:** Detects injection-related environment variables

**How it works:**
- Checks for DYLD_INSERT_LIBRARIES and related variables
- Detects Substrate environment markers

**Implementation:** `RuntimeIntegrityChecker.checkEnvironmentVariables()`

**Effectiveness:** High - very reliable for detecting dylib injection

---
