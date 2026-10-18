import Foundation

// LuLuManifest's pure target-policy check only needs the decoded target ID;
// this fixture keeps the test independent of process launch APIs.
struct LegacyTarget: Decodable { let targetID: String }

@main private struct LuLuManifestTargetAvailabilityTests {
    static func main() {
        let active = ["claude", "adspower"]
        let explicitlyDisabled = ["ccbaga_browser", "claude_code", "mcp"]
        precondition(LuLuManifest.targetPolicyValid(legacyTargetIDs: active,
                                                    disabledTargetIDs: explicitlyDisabled))

        // The new two-entry service requires an explicitly reviewed deployment.
        precondition(!LuLuManifest.targetPolicyValid(legacyTargetIDs: active,
                                                     disabledTargetIDs: ["ccbaga_browser", "claude_code", "mcp", "sunbrowser"]))
        precondition(!LuLuManifest.targetPolicyValid(legacyTargetIDs: ["claude", "claude"],
                                                     disabledTargetIDs: explicitlyDisabled))
        print("LuLu two-entry manifest fixtures passed")
    }
}
