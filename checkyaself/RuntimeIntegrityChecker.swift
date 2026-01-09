//
//  RuntimeIntegrityChecker.swift
//  Check ya self
//
//  Runtime integrity checks - checksums, anti-hook detection
//

import Foundation
import CommonCrypto
import MachO

nonisolated class RuntimeIntegrityChecker {

    // MARK: - Code Segment Checksums
    
    /// Calculates and verifies checksums of executable segments
    /// Note: Store expected checksums separately and compare at runtime
    static func calculateExecutableChecksum() -> String? {
        guard let executablePath = Bundle.main.executablePath else {
            return nil
        }
        
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: executablePath)) else {
            return nil
        }
        
        // Calculate SHA256 of the executable
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        
        return hash.map { String(format: "%02x", $0) }.joined()
    }
    
    /// Calculates checksum of a specific function/method
    /// Useful for protecting critical security functions
    static func calculateFunctionChecksum(functionPointer: UnsafeRawPointer, length: Int) -> String {
        let data = Data(bytes: functionPointer, count: length)
        
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        
        return hash.map { String(format: "%02x", $0) }.joined()
    }
    
    // MARK: - Method Swizzling Detection
    
    /// Detects if a method has been swizzled/hooked
    static func isMethodSwizzled(class: AnyClass, selector: Selector, expectedImplementation: IMP) -> Bool {
        guard let method = class_getInstanceMethod(`class`, selector) else {
            return true // Method doesn't exist - suspicious
        }
        
        let currentImplementation = method_getImplementation(method)
        
        // Compare implementation pointers
        return currentImplementation != expectedImplementation
    }
    
    /// Checks if any NSObject methods have been swizzled (common attack vector)
    static func detectCommonSwizzling() -> Bool {
        // Check if common methods are hooked
        let nsObjectClass: AnyClass = NSObject.self
        
        // These are commonly hooked methods - check if they point to unexpected implementations
        let suspiciousSelectors = [
            #selector(NSObject.responds(to:)),
            #selector(NSObject.isKind(of:)),
        ]
        
        for selector in suspiciousSelectors {
            if let method = class_getInstanceMethod(nsObjectClass, selector) {
                let imp = method_getImplementation(method)
                
                // Check if implementation is in a suspicious library
                var info = Dl_info()
                if dladdr(unsafeBitCast(imp, to: UnsafeRawPointer.self), &info) != 0 {
                    if let imageName = info.dli_fname {
                        let name = String(cString: imageName).lowercased()
                        // Check if the implementation is from a hooking framework
                        if name.contains("substrate") || name.contains("frida") || 
                           name.contains("cycript") || name.contains("cynject") {
                            return true
                        }
                    }
                }
            }
        }
        
        return false
    }
    
    // MARK: - Inline Hook Detection
    
    /// Checks for trampolines/patches at function entry points
    static func checkForInlineHook(functionPointer: UnsafeRawPointer) -> Bool {
        let bytes = functionPointer.bindMemory(to: UInt8.self, capacity: 16)
        
        // Check for common hook patterns on ARM64
        // Look for branch instructions that might be hooks
        
        // ARM64 branch instruction patterns:
        // B (unconditional branch): 0x14000000 (bits 31-26 = 000101)
        // BL (branch with link): 0x94000000 (bits 31-26 = 100101)
        
        let instruction = UInt32(bytes[0]) | 
                         (UInt32(bytes[1]) << 8) | 
                         (UInt32(bytes[2]) << 16) | 
                         (UInt32(bytes[3]) << 24)
        
        // Check if first instruction is an unconditional branch (suspicious for hooks)
        let opcode = (instruction >> 26) & 0x3F
        if opcode == 0x05 || opcode == 0x25 {
            // This might be a hook, but could also be legitimate
            // More sophisticated analysis would be needed
            return true
        }
        
        return false
    }
    
    // MARK: - Dynamic Symbol Resolution Check
    
    /// Checks if symbols have been rebound (common in hooking)
    static func checkSymbolBinding() -> Bool {
        // Check if certain security-critical symbols have been rebound
        let criticalSymbols = ["ptrace", "sysctl", "dlopen", "dlsym"]
        
        for symbol in criticalSymbols {
            if let handle = dlopen(nil, RTLD_NOW) {
                if let symbolAddr = dlsym(handle, symbol) {
                    var info = Dl_info()
                    if dladdr(symbolAddr, &info) != 0 {
                        if let imageName = info.dli_fname {
                            let name = String(cString: imageName).lowercased()
                            // Check if symbol is from an unexpected library
                            if !name.contains("libsystem") && !name.contains("system") {
                                dlclose(handle)
                                return true // Symbol rebound to suspicious library
                            }
                        }
                    }
                }
                dlclose(handle)
            }
        }
        
        return false
    }
    
    // MARK: - Memory Protection Check
    
    /// Checks if code segment memory protections have been modified
    static func checkMemoryProtections() -> Bool {
        // Note: This is a simplified check as direct memory protection inspection is limited on iOS
        // We can check if we can read the executable header
        guard let executablePath = Bundle.main.executablePath else {
            return false
        }
        
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: executablePath), options: [.mappedIfSafe]),
              data.count >= MemoryLayout<mach_header_64>.size else {
            return false
        }
        
        // Read the Mach-O header
        let header = data.withUnsafeBytes { $0.load(as: mach_header_64.self) }
        
        // Check if magic number is valid
        if header.magic != MH_MAGIC_64 && header.magic != MH_CIGAM_64 {
            return true // Header tampered
        }
        
        return false
    }
    
    // MARK: - Objective-C Runtime Checks
    
    /// Checks for suspicious classes injected at runtime
    static func detectInjectedClasses() -> Bool {
        var count: UInt32 = 0
        let classListPtr = objc_copyClassList(&count)
        defer {
          free(UnsafeMutableRawPointer(classListPtr))
        }
        let classListBuffer = UnsafeBufferPointer(
          start: classListPtr, count: Int(count)
        )

        let suspiciousClassPrefixes = [
            "Frida",
            "Cycript", 
            "Substrate",
            "MSHook",
            "CY",
            "Reveal", // Reveal inspector
            "InjectionBundle"
        ]
        
        var result = false
        
        for i in 0..<Int(count) {
            let classObject: AnyClass = classListBuffer[Int(i)]

            // Filter out "weird" base classes without superclasses to avoid Swift runtime crashes
            // See: https://developer.apple.com/forums/thread/767346
            guard class_getSuperclass(classObject) != nil else {
                continue
            }
            
            let className = String(cString: class_getName(classObject))
            
            for prefix in suspiciousClassPrefixes {
                if className.hasPrefix(prefix) {
                    result = true
                    break
                }
            }
            
            if result {
                break
            }
        }

        return result
    }
    
    /// Checks if suspicious protocols have been registered
    static func detectSuspiciousProtocols() -> Bool {
        var protocolCount: UInt32 = 0
        guard let protocolList = objc_copyProtocolList(&protocolCount) else {
            return false
        }
        
        let suspiciousProtocols = [
            "CydgetProtocol",
            "SubstrateProtocol"
        ]
        
        var result = false
        
        for i in 0..<Int(protocolCount) {
            let proto = protocolList[Int(i)]
            let protocolName = String(cString: protocol_getName(proto))
            
            if suspiciousProtocols.contains(protocolName) {
                result = true
                break
            }
        }
        
        // Free the allocated memory
        free(UnsafeMutableRawPointer(protocolList))
        
        return result
    }
    
    // MARK: - Anti-Debug Enhancement
    
    /// Continuous debugger check with timing
    static func continuousDebuggerCheck() async {
        while true {
            var info = kinfo_proc()
            var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
            var size = MemoryLayout<kinfo_proc>.stride
            
            let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
            
            if result == 0 {
                let debuggerAttached = (info.kp_proc.p_flag & P_TRACED) != 0
                if debuggerAttached {
                    // Handle debugger detection - could throw, return, or notify via AsyncStream
                    break
                }
            }
            
            // Random sleep to make timing attacks harder
            let randomSleep = UInt64.random(in: 1_000_000_000...5_000_000_000) // 1-5 seconds in nanoseconds
            try? await Task.sleep(nanoseconds: randomSleep)
        }
    }
    
    // MARK: - Environment Variable Checks
    
    /// Checks for suspicious environment variables
    static func checkEnvironmentVariables() -> Bool {
        let suspiciousVars = [
            "DYLD_INSERT_LIBRARIES",
            "DYLD_FORCE_FLAT_NAMESPACE",
            "_MSSafeMode",
            "SubstrateLoader",
            "MobileSubstrate"
        ]
        
        for varName in suspiciousVars {
            if getenv(varName) != nil {
                // Variable exists
                return true
            }
        }
        
        return false
    }
}

// MARK: - Extension for SecurityManager Integration

nonisolated extension SecurityManager {

    /// Performs advanced runtime integrity checks
    static func performAdvancedChecks() -> AdvancedSecurityCheckResults {
        var results = AdvancedSecurityCheckResults()
        
        results.methodSwizzlingDetected = RuntimeIntegrityChecker.detectCommonSwizzling()
        results.symbolBindingTampered = RuntimeIntegrityChecker.checkSymbolBinding()
        results.injectedClassesDetected = RuntimeIntegrityChecker.detectInjectedClasses()
        results.suspiciousProtocolsDetected = RuntimeIntegrityChecker.detectSuspiciousProtocols()
        results.suspiciousEnvironmentVariables = RuntimeIntegrityChecker.checkEnvironmentVariables()
        
        return results
    }
}

// MARK: - Advanced Results Structure

nonisolated struct AdvancedSecurityCheckResults {
    var methodSwizzlingDetected = false
    var symbolBindingTampered = false
    var injectedClassesDetected = false
    var suspiciousProtocolsDetected = false
    var suspiciousEnvironmentVariables = false
    
    var isSecure: Bool {
        return !methodSwizzlingDetected &&
               !symbolBindingTampered &&
               !injectedClassesDetected &&
               !suspiciousProtocolsDetected &&
               !suspiciousEnvironmentVariables
    }
    
    var failureReasons: [String] {
        var reasons: [String] = []
        
        if methodSwizzlingDetected {
            reasons.append("Method swizzling detected")
        }
        if symbolBindingTampered {
            reasons.append("Symbol binding tampered")
        }
        if injectedClassesDetected {
            reasons.append("Injected classes detected")
        }
        if suspiciousProtocolsDetected {
            reasons.append("Suspicious protocols detected")
        }
        if suspiciousEnvironmentVariables {
            reasons.append("Suspicious environment variables")
        }
        
        return reasons
    }
}
