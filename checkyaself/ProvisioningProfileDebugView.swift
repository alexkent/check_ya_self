//
//  ProvisioningProfileDebugView.swift
//  Check ya self
//
//  Debug view to inspect provisioning profile parsing
//

import SwiftUI

struct ProvisioningProfileDebugView: View {
    @State private var profileInfo: String = "Loading..."
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text(profileInfo)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .padding()
                    .background(Color.secondary.opacity(0.1))
                    .cornerRadius(8)
            }
            .padding()
        }
        .navigationTitle("Provisioning Profile")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            loadProfileInfo()
        }
    }
    
    private func loadProfileInfo() {
        Task.detached {
            var info = ""
            
            // Check if profile exists
            if let path = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision") {
                info += "✅ Profile found at: \(path)\n\n"
                
                // Try to read raw data
                if let data = try? Data(contentsOf: URL(fileURLWithPath: path)) {
                    info += "✅ Profile size: \(data.count) bytes\n\n"
                    
                    // Try to parse
                    if let profile = ProvisioningProfileParser.parse() {
                        info += "✅ Successfully parsed profile\n\n"
                        info += "Profile Contents:\n"
                        info += "----------------\n\n"
                        
                        for (key, value) in profile.sorted(by: { $0.key < $1.key }) {
                            info += "\(key): "
                            
                            if let stringValue = value as? String {
                                info += "\(stringValue)\n"
                            } else if let arrayValue = value as? [Any] {
                                info += "[\(arrayValue.count) items]\n"
                                if key == "TeamIdentifier", let teamIds = arrayValue as? [String] {
                                    for teamId in teamIds {
                                        info += "  - \(teamId)\n"
                                    }
                                }
                            } else if let dictValue = value as? [String: Any] {
                                info += "{\(dictValue.count) keys}\n"
                                if key == "Entitlements" {
                                    for (entKey, entValue) in dictValue.sorted(by: { $0.key < $1.key }) {
                                        info += "  - \(entKey): \(entValue)\n"
                                    }
                                }
                            } else {
                                info += "\(type(of: value))\n"
                            }
                        }
                    } else {
                        info += "❌ Failed to parse profile\n\n"
                        
                        // Try different encodings
                        if let isoString = String(data: data, encoding: .isoLatin1) {
                            info += "Profile contains XML: \(isoString.contains("<?xml"))\n"
                            info += "Profile contains </plist>: \(isoString.contains("</plist>"))\n\n"
                            
                            if let startRange = isoString.range(of: "<?xml"),
                               let endRange = isoString.range(of: "</plist>") {
                                let xmlLength = isoString.distance(from: startRange.lowerBound, to: endRange.upperBound)
                                info += "XML plist section length: \(xmlLength) characters\n\n"
                                
                                let plistString = String(isoString[startRange.lowerBound..<endRange.upperBound])
                                info += "First 500 chars of plist:\n"
                                info += String(plistString.prefix(500))
                                info += "\n..."
                            }
                        } else {
                            info += "❌ Could not decode profile as ISO Latin 1\n"
                        }
                    }
                } else {
                    info += "❌ Could not read profile data\n"
                }
            } else {
                info += "❌ No embedded.mobileprovision found\n"
                info += "This is normal in simulator\n"
            }

            let out = info
            await MainActor.run {
                self.profileInfo = out
            }
        }
    }
}

// Helper to expose the private parsing method for debugging
struct ProvisioningProfileParser {
    static nonisolated func parse() -> [String: Any]? {
        guard let provisioningPath = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision") else {
            return nil
        }
        
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: provisioningPath)) else {
            return nil
        }
        
        guard let dataString = String(data: data, encoding: .isoLatin1) else {
            return nil
        }
        
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

#Preview {
    NavigationView {
        ProvisioningProfileDebugView()
    }
}
