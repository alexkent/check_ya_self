//
//  SecurityCheckView.swift
//  Check ya self
//
//  Demonstrates security check results
//

import SwiftUI

struct SecurityCheckView: View {
    @State private var results: SecurityCheckResults?
    @State private var advancedResults: AdvancedSecurityCheckResults?
    @State private var isLoading = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {

                // Overall Status
                if let results = results, let advancedResults = advancedResults {
                    let overallSecure = results.isSecure && advancedResults.isSecure
                    overallStatusView(results, advancedResults: advancedResults)
                        .padding()
                        .background(overallSecure ? Color.green.opacity(0.2) : Color.red.opacity(0.2))
                        .cornerRadius(12)
                }

                // Basic Security Checks
                VStack(alignment: .leading, spacing: 12) {
                    Text("Basic Security Checks")
                        .font(.headline)
                    
                    if let results = results {
                        checkRow(title: "Code Signature", passed: results.codeSignatureValid)
                        checkRow(title: "Bundle ID", passed: results.bundleIDValid)
                        checkRow(title: "Team ID", passed: results.teamIDValid)
                        checkRow(title: "Entitlements", passed: results.entitlementsValid)
                        checkRow(title: "No Debugger", passed: !results.debuggerDetected)
                        checkRow(title: "Not Jailbroken", passed: !results.jailbroken)
                        checkRow(title: "No Suspicious Libraries", passed: !results.suspiciousLibrariesDetected)
                    }
                }
                
                // Advanced Runtime Integrity Checks
                VStack(alignment: .leading, spacing: 12) {
                    Text("Advanced Runtime Checks")
                        .font(.headline)
                    
                    if let advancedResults = advancedResults {
                        checkRow(title: "No Method Swizzling", passed: !advancedResults.methodSwizzlingDetected)
                        checkRow(title: "Symbol Binding Intact", passed: !advancedResults.symbolBindingTampered)
                        checkRow(title: "No Injected Classes", passed: !advancedResults.injectedClassesDetected)
                        checkRow(title: "No Suspicious Protocols", passed: !advancedResults.suspiciousProtocolsDetected)
                        checkRow(title: "Clean Environment", passed: !advancedResults.suspiciousEnvironmentVariables)
                    }
                }

                // Failure Reasons
                if let results = results, let advancedResults = advancedResults {
                    let allReasons = results.failureReasons + advancedResults.failureReasons
                    if !allReasons.isEmpty {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Issues Detected")
                                .font(.headline)
                                .foregroundColor(.red)
                            
                            ForEach(allReasons, id: \.self) { reason in
                                HStack {
                                    Image(systemName: "exclamationmark.triangle.fill")
                                        .foregroundColor(.orange)
                                    Text(reason)
                                        .font(.subheadline)
                                }
                            }
                        }
                        .padding()
                        .background(Color.orange.opacity(0.1))
                        .cornerRadius(12)
                    }
                }

                // Actions
                VStack(alignment: .leading, spacing: 12) {
                    NavigationLink(destination: LoadedLibrariesView()) {
                        Label("View Loaded Libraries", systemImage: "list.bullet")
                    }
                    .buttonStyle(.bordered)

                    NavigationLink(destination: ProvisioningProfileDebugView()) {
                        Label("View Provisioning Profile", systemImage: "pencil.and.list.clipboard")
                    }
                    .buttonStyle(.bordered)
                }

                // Information
                VStack(alignment: .leading, spacing: 8) {
                    Text("About These Checks")
                        .font(.headline)

                    Text("""
                        These security checks implement defense-in-depth strategies:
                        
                        **Basic Checks:**
                        • Code Signature, Bundle/Team ID, Entitlements
                        • Debugger, Jailbreak, Library Injection Detection
                        
                        **Advanced Runtime Checks:**
                        • Method Swizzling Detection
                        • Symbol Binding Tampering
                        • Injected Classes/Protocols
                        • Environment Variable Checks
                        """)
                    .font(.caption)
                    .foregroundColor(.secondary)
                }
                .padding()
                .background(Color.secondary.opacity(0.1))
                .cornerRadius(12)
            }
            .padding()
            .onAppear {
                performChecks()
            }
        }
        .navigationTitle("Security Check")
    }

    private func overallStatusView(_ results: SecurityCheckResults, advancedResults: AdvancedSecurityCheckResults) -> some View {
        let overallSecure = results.isSecure && advancedResults.isSecure
        let totalIssues = results.failureReasons.count + advancedResults.failureReasons.count
        
        return HStack {
            Image(systemName: overallSecure ? "checkmark.shield.fill" : "xmark.shield.fill")
                .font(.largeTitle)
                .foregroundColor(overallSecure ? .green : .red)
            
            VStack(alignment: .leading) {
                Text(overallSecure ? "Secure" : "Security Issues Detected")
                    .font(.title2)
                    .fontWeight(.bold)
                
                if !overallSecure {
                    Text("\(totalIssues) issue(s) found")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
            }
            
            Spacer()
        }
    }

    private func checkRow(title: String, passed: Bool) -> some View {
        HStack {
            Image(systemName: passed ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundColor(passed ? .green : .red)
            Text(title)
            Spacer()
        }
        .padding(.vertical, 4)
    }

    private func performChecks() {
        isLoading = true
        
        // Perform checks asynchronously to avoid blocking UI
        DispatchQueue.global(qos: .userInitiated).async {
            let checkResults = SecurityManager.performSecurityChecks()
            let advancedCheckResults = SecurityManager.performAdvancedChecks()
            
            DispatchQueue.main.async {
                self.results = checkResults
                self.advancedResults = advancedCheckResults
                self.isLoading = false
            }
        }
    }
}

// MARK: - Loaded Libraries View

struct LoadedLibrariesView: View {
    @State private var libraries: [String] = []
    @State private var searchText = ""
    
    var filteredLibraries: [String] {
        if searchText.isEmpty {
            return libraries
        }
        return libraries.filter { library in
            library.lowercased().contains(searchText.lowercased())
        }
    }
    
    var body: some View {
        List {
            if libraries.isEmpty {
                Text("Loading...")
            } else {
                ForEach(filteredLibraries, id: \.self) { library in
                    VStack(alignment: .leading) {
                        Text(URL(fileURLWithPath: library).lastPathComponent)
                            .font(.headline)
                        Text(library)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    .padding(.vertical, 4)
                }
            }
        }
        .searchable(text: $searchText, prompt: "Search libraries")
        .navigationTitle("Loaded Libraries (\(filteredLibraries.count))")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            loadLibraries()
        }
    }

    private func loadLibraries() {
        DispatchQueue.global(qos: .userInitiated).async {
            let libs = SecurityManager.getLoadedLibraries()

            DispatchQueue.main.async {
                self.libraries = libs
            }
        }
    }
}

#Preview {
    SecurityCheckView()
}
