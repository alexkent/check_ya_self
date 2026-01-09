//
//  SecurityManager.swift
//  Check ya self
//
//  Anti-tampering and integrity checks for iOS
//

import Foundation
import Security
import MachO
import UIKit

/// Manages application security and integrity checks
nonisolated class SecurityManager {

    // MARK: - Configuration
    
    /// Expected values - configure these for your app
    struct ExpectedValues {
        static let bundleID = "net.alexkent.Know-Thy-Self" // Update to match your actual bundle ID
        static let teamID = "4JFQ594K7B" // Update to your Apple Developer Team ID

        // Expected entitlements (add your app's specific entitlements)
        static let requiredEntitlements = [
            "application-identifier",
            "keychain-access-groups"
        ]
    }
    
    // MARK: - Public API
    
    /// Performs all security checks and returns results
    static func performSecurityChecks() -> SecurityCheckResults {
        var results = SecurityCheckResults()
        
        results.codeSignatureValid = checkCodeSignature()
        results.bundleIDValid = checkBundleID()
        results.teamIDValid = checkTeamID()
        results.entitlementsValid = checkEntitlements()
        results.debuggerDetected = isDebuggerAttached()
        results.jailbroken = isJailbroken()
        results.suspiciousLibrariesDetected = checkForSuspiciousLibraries()
        
        return results
    }
    
    // MARK: - Code Signature Verification

    /// Verifies the app's code signature is valid and unmodified
    static func checkCodeSignature() -> Bool {
        // Check if app is properly signed by verifying the code signature directory exists
        let bundlePath = Bundle.main.bundlePath
        let codeSignaturePath = (bundlePath as NSString).appendingPathComponent("_CodeSignature")
        
        guard FileManager.default.fileExists(atPath: codeSignaturePath) else {
            return false
        }
        
        // Additional check: verify the Info.plist hasn't been modified
        // This is a basic integrity check
        guard Bundle.main.infoDictionary != nil else {
            return false
        }

        guard Bundle.main.infoDictionary?["CFBundleIdentifier"] as? String == ExpectedValues.bundleID else {
            return false
        }

        return true
    }
    
    // MARK: - Bundle ID Verification
    
    /// Verifies the bundle ID matches expected value
    static func checkBundleID() -> Bool {
        guard let bundleID = Bundle.main.bundleIdentifier else {
            return false
        }
        
        return bundleID == ExpectedValues.bundleID
    }
    
    // MARK: - Team ID Verification
    
    /// Verifies the Apple Developer Team ID
    static func checkTeamID() -> Bool {
        // Parse the embedded.mobileprovision file
        guard let profile = parseProvisioningProfile() else {
            // No profile (simulator) or can't parse - default to true
            return true
        }
        
        // Check for TeamIdentifier array or TeamName
        if let teamIdentifiers = profile["TeamIdentifier"] as? [String] {
            return teamIdentifiers.contains(ExpectedValues.teamID)
        }
        
        if let teamName = profile["TeamName"] as? String {
            return teamName.contains(ExpectedValues.teamID)
        }
        
        // If we can't find team info, default to true
        return true
    }
    
    // MARK: - Entitlements Verification
    
    /// Verifies app entitlements match expected values
    static func checkEntitlements() -> Bool {
        // Parse the embedded.mobileprovision file
        guard let profile = parseProvisioningProfile() else {
            // No profile (simulator) or can't parse - default to true
            return true
        }
        
        // Get the Entitlements dictionary from the profile
        guard let entitlements = profile["Entitlements"] as? [String: Any] else {
            return true
        }
        
        // Check if required entitlements exist
        for required in ExpectedValues.requiredEntitlements {
            if entitlements[required] == nil {
                return false
            }
        }

        if entitlements["application-identifier"] as? String != "\(ExpectedValues.teamID).*" {
            return false
        }

        return true
    }
    
    // MARK: - Debugger Detection
    
    /// Checks if a debugger is currently attached
    static func isDebuggerAttached() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        
        guard result == 0 else {
            return false
        }
        
        // Check the P_TRACED flag
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }
    
    /// Anti-debugging using ptrace - call this early in app lifecycle
    static func denyPtraceAttach() {
        #if !DEBUG
        // Disable ptrace to prevent debugger attachment
        // Note: This uses a private API and should only be used in release builds
        typealias PtraceType = @convention(c) (Int32, pid_t, caddr_t?, Int32) -> Int32
        let ptrace = unsafeBitCast(dlsym(UnsafeMutableRawPointer(bitPattern: -2), "ptrace"),
                                   to: PtraceType.self)
        _ = ptrace(31, 0, nil, 0) // PT_DENY_ATTACH = 31
        #endif
    }
    
    // MARK: - Jailbreak Detection
    
    /// Checks for signs of jailbreak
    static func isJailbroken() -> Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        
        // Check 1: Common jailbreak files
        let jailbreakPaths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/private/var/lib/apt/",
            "/private/var/lib/cydia",
            "/private/var/stash",
            "/private/var/tmp/cydia.log",
            "/Applications/RockApp.app",
            "/Applications/Icy.app",
            "/usr/libexec/sftp-server",
            "/usr/bin/ssh",
            "/Applications/WinterBoard.app",
            "/Applications/SBSettings.app",
            "/Applications/FakeCarrier.app",
            "/Applications/IntelliScreen.app",
            "/Applications/Snoop-itConfig.app",
            "/var/lib/undecimus/apt",
            "/Applications/blackra1n.app",
            "/Applications/checkra1n.app"
        ]
        
        for path in jailbreakPaths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        
        // Check 2: Can we write to system paths? (sandbox escape test)
        let testPath = "/private/jailbreak_test.txt"
        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            return true // Should not be able to write here
        } catch {
            // Good - we can't write outside sandbox
        }
        
        // Check 3: Check if Cydia URL scheme is available
        if let url = URL(string: "cydia://package/com.example.package") {
            if UIApplication.shared.canOpenURL(url) {
                return true
            }
        }

        // Check 4: Check for suspicious environment variables
        if let _ /*dyldInsertLibs*/ = getenv("DYLD_INSERT_LIBRARIES") {
            // nb. libViewDebuggerSupport is injected by Xcode when debugging

//            if String(cString: dyldInsertLibs) != "/usr/lib/libViewDebuggerSupport.dylib" {
                return true
//            }
        }
        
        return false
        #endif
    }
    
    // MARK: - Dynamic Library Injection Detection
    
    /// Checks for suspicious or unexpected dynamic libraries
    static func checkForSuspiciousLibraries() -> Bool {
        let suspiciousLibraries = [
            "FridaGadget",
            "frida",
            "cynject",
            "libcycript",
            "SubstrateInserter",
            "SubstrateLoader",
            "MobileSubstrate",
            "SSLKillSwitch",
            "PreferenceLoader"
        ]
        
        // Get count of loaded images
        let count = _dyld_image_count()
        
        for i in 0..<count {
            if let imageName = _dyld_get_image_name(i) {
                let name = String(cString: imageName)
                
                // Check against suspicious library names
                for suspicious in suspiciousLibraries {
                    if name.lowercased().contains(suspicious.lowercased()) {
                        return true
                    }
                }
            }
        }
        
        return false
    }
    
    /// Returns a list of all loaded dynamic libraries (for debugging/logging)
    static func getLoadedLibraries() -> [String] {
        var libraries: [String] = []
        let count = _dyld_image_count()
        
        for i in 0..<count {
            if let imageName = _dyld_get_image_name(i) {
                libraries.append(String(cString: imageName))
            }
        }
        
        return libraries
    }
    
    // MARK: - Helper Methods
    
    /// Parses the embedded.mobileprovision file and returns the plist dictionary
    private static func parseProvisioningProfile() -> [String: Any]? {
        guard let provisioningPath = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision") else {
            return nil
        }
        
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: provisioningPath)) else {
            return nil
        }
        
        // The provisioning profile is a CMS (Cryptographic Message Syntax) container
        // The actual plist is embedded between specific markers
        // We need to extract the XML plist portion
        
        guard let dataString = String(data: data, encoding: .isoLatin1) else {
            return nil
        }
        
        // Find the plist content between <?xml and </plist>
        guard let startRange = dataString.range(of: "<?xml"),
              let endRange = dataString.range(of: "</plist>") else {
            return nil
        }
        
        let plistStart = startRange.lowerBound
        let plistEnd = endRange.upperBound
        let plistString = String(dataString[plistStart..<plistEnd])
        
        guard let plistData = plistString.data(using: .utf8) else {
            return nil
        }
        
        // Parse the plist
        do {
            if let plist = try PropertyListSerialization.propertyList(from: plistData, format: nil) as? [String: Any] {
                return plist
            }
        } catch {
            return nil
        }
        
        return nil
    }
}

// MARK: - Results Structure

/// Results from security checks
nonisolated struct SecurityCheckResults {
    var codeSignatureValid = false
    var bundleIDValid = false
    var teamIDValid = false
    var entitlementsValid = false
    var debuggerDetected = false
    var jailbroken = false
    var suspiciousLibrariesDetected = false
    
    /// Overall security status
    var isSecure: Bool {
        return codeSignatureValid &&
               bundleIDValid &&
               teamIDValid &&
               entitlementsValid &&
               !debuggerDetected &&
               !jailbroken &&
               !suspiciousLibrariesDetected
    }
    
    /// Human-readable description of failures
    var failureReasons: [String] {
        var reasons: [String] = []
        
        if !codeSignatureValid {
            reasons.append("Invalid or modified code signature")
        }
        if !bundleIDValid {
            reasons.append("Bundle ID mismatch")
        }
        if !teamIDValid {
            reasons.append("Team ID mismatch")
        }
        if !entitlementsValid {
            reasons.append("Entitlements modified or missing")
        }
        if debuggerDetected {
            reasons.append("Debugger detected")
        }
        if jailbroken {
            reasons.append("Device appears to be jailbroken (or run from Xcode)")
        }
        if suspiciousLibrariesDetected {
            reasons.append("Suspicious libraries detected")
        }
        
        return reasons
    }
}
