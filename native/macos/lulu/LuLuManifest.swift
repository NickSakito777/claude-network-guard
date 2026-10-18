import Foundation
import Darwin
import Security
import CryptoKit

// User-level, bundle-sealed configuration for the existing LuLu enforcement
// boundary. It is NOT a privileged NE authority or a hostile-user sandbox.
struct LuLuManifest: Decodable {
    struct Baseline: Decodable {
        let path: String
        let digests: [String]
        let maximumBytes: Int
    }
    let schemaVersion: Int
    let route: String
    let controllerBundleID: String
    let controllerUID: UInt32
    let home: String
    let pythonExecutable: String
    let factsScriptSHA256: String
    let firewallPolicySHA: String
    let baselineFiles: [Baseline]
    let legacyTargets: [LegacyTarget]
    let disabledTargets: [String]

    static let requiredLegacyTargetIDs: Set<String> = ["claude", "adspower"]
    static let requiredDisabledTargetIDs: Set<String> = [
        "ccbaga_browser", "claude_code", "mcp"
    ]

    static func targetPolicyValid(legacyTargetIDs: [String],
                                  disabledTargetIDs: [String]) -> Bool {
        legacyTargetIDs.count == requiredLegacyTargetIDs.count &&
            Set(legacyTargetIDs) == requiredLegacyTargetIDs &&
            disabledTargetIDs.count == requiredDisabledTargetIDs.count &&
            Set(disabledTargetIDs) == requiredDisabledTargetIDs
    }

    var factsScriptURL: URL {
        Bundle.main.resourceURL!.appendingPathComponent("lulu_facts.py")
    }

    static func production() throws -> Self {
        guard let resources = Bundle.main.resourceURL,
              let pw = getpwuid(getuid()) else { throw NativeControlError.unavailable("lulu_bundle") }
        let url = resources.appendingPathComponent("lulu-manifest.json")
        var entry = stat()
        let manifestExists = url.path.withCString { lstat($0, &entry) == 0 }
        if !manifestExists && errno == ENOENT {
            throw NativeControlError.unavailable("deployment_manifest_missing")
        }
        let bytes = try ProtectedFiles.read(url.path, maximum: 131_072, owner: nil)
        let value = try JSONDecoder().decode(Self.self, from: bytes)
        guard value.schemaVersion == 1, value.route == "lulu-existing-v1",
              value.controllerBundleID == "local.fox.guard",
              value.controllerUID == getuid(), getuid() == geteuid(), getuid() > 0,
              value.home == String(cString: pw.pointee.pw_dir),
              Self.targetPolicyValid(legacyTargetIDs: value.legacyTargets.map(\.targetID),
                                     disabledTargetIDs: value.disabledTargets),
              (4...32).contains(value.baselineFiles.count),
              Set(value.baselineFiles.map(\.path)).count == value.baselineFiles.count,
              digestText(value.firewallPolicySHA), digestText(value.factsScriptSHA256) else {
            throw NativeControlError.rejected("lulu_manifest_schema")
        }
        let required = [value.pythonExecutable,
            value.home + "/.local/share/claude-network-guard/config.json",
            value.home + "/.local/share/claude-network-guard/verified-deployment.json",
            value.home + "/Library/Application Support/com.follow.clash/config.yaml"]
        guard required.allSatisfy({ required in value.baselineFiles.contains { $0.path == required } }),
              !value.baselineFiles.contains(where: { $0.path == "/Library/Objective-See/LuLu/rules.plist" || $0.path == "/Library/Objective-See/LuLu/preferences.plist" }) else {
            throw NativeControlError.rejected("lulu_manifest_baselines")
        }
        try value.verify()
        return value
    }

    func verify() throws {
        guard Bundle.main.bundleIdentifier == controllerBundleID,
              getuid() == controllerUID, geteuid() == controllerUID else {
            throw NativeControlError.rejected("lulu_controller_identity")
        }
        // An ad-hoc bundle seal is sufficient for accidental change detection
        // here; no Apple paid entitlement is consumed. LuLu owns OS filtering.
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(Bundle.main.bundleURL as CFURL, [], &code) == errSecSuccess,
              let code, SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), nil) == errSecSuccess else {
            throw NativeControlError.rejected("lulu_bundle_changed")
        }
        for baseline in baselineFiles {
            guard (1...67_108_864).contains(baseline.maximumBytes),
                  (1...4).contains(baseline.digests.count), baseline.digests.allSatisfy(Self.digestText) else {
                throw NativeControlError.rejected("baseline_schema")
            }
            let data = try ProtectedFiles.read(baseline.path, maximum: baseline.maximumBytes, owner: nil)
            guard baseline.digests.contains(Self.digest(data)) else {
                throw NativeControlError.rejected("lulu_baseline_changed_" + URL(fileURLWithPath: baseline.path).lastPathComponent)
            }
        }
        let facts = try ProtectedFiles.read(factsScriptURL.path, maximum: 65_536, owner: nil)
        guard Self.digest(facts) == factsScriptSHA256 else { throw NativeControlError.rejected("lulu_facts_helper_changed") }
    }

    private static func digest(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }
    private static func digestText(_ text: String) -> Bool {
        text.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil
    }
}
