import CryptoKit
import Darwin
import Foundation

enum LuLuAtom: Codable, Equatable {
    case null, bool(Bool), int(Int), string(String)

    init(from decoder: Decoder) throws {
        let value = try decoder.singleValueContainer()
        if value.decodeNil() { self = .null }
        else if let item = try? value.decode(Bool.self) { self = .bool(item) }
        else if let item = try? value.decode(Int.self) { self = .int(item) }
        else if let item = try? value.decode(String.self) { self = .string(item) }
        else { throw DecodingError.dataCorruptedError(in: value, debugDescription: "unsupported atom") }
    }
    func encode(to encoder: Encoder) throws {
        var value = encoder.singleValueContainer()
        switch self {
        case .null: try value.encodeNil()
        case .bool(let item): try value.encode(item)
        case .int(let item): try value.encode(item)
        case .string(let item): try value.encode(item)
        }
    }
    var text: String? { if case .string(let value) = self { return value }; return nil }
    var integer: Int? { if case .int(let value) = self { return value }; return nil }
    var off: Bool {
        switch self { case .null, .bool(false), .int(0), .string(""): return true
        default: return false }
    }
}

struct LuLuRule: Codable, Equatable {
    let key: LuLuAtom
    let path: LuLuAtom
    let endpointAddr: LuLuAtom
    let endpointPort: LuLuAtom
    let action: LuLuAtom
    let isEndpointAddrRegex: LuLuAtom
    let isDisabled: LuLuAtom
    let pid: LuLuAtom
    let expiration: LuLuAtom
    let scope: LuLuAtom
    let type: LuLuAtom
    let endpointHost: LuLuAtom

    var fields: [(String, LuLuAtom)] {
        [("action", action), ("endpointAddr", endpointAddr),
         ("endpointPort", endpointPort), ("expiration", expiration),
         ("isDisabled", isDisabled), ("isEndpointAddrRegex", isEndpointAddrRegex),
         ("key", key), ("path", path), ("pid", pid)]
    }
}

struct LuLuFacts: Codable {
    let schemaVersion: Int
    let home: String
    let preferencesFileSHA256: String
    let rulesFileSHA256: String
    let preferences: [String: LuLuAtom]
    let rules: [LuLuRule]
}

enum LuLuPolicyError: Error, Equatable {
    case wrongScope, sourceChanged, globalException, malformedRule
    case temporaryRule, missingDeny(String), missingAllow(String)
    case extraAllow, legacyDigestChanged, helperUnavailable, helperOutputInvalid
    case unsupportedScope, metadataChanged
}

// This proves only that decoded on-disk rule facts match a reviewed snapshot.
// Installed LuLu extension state and actual kernel enforcement are separate.
struct LuLuPolicyEvidence {
    let legacyDigest: String
    let selectedRuleCount: Int
    let rulesFileSHA256: String
    let preferencesFileSHA256: String
}

enum LuLuPolicy {
    private static let claude = "/Applications/Claude.app"
    private static let claudeRoot = "/Applications/Claude.app/Contents/"
    private static let sunSuffix = "/Library/Application Support/adspower_global/cwd_global/"
    private static let preferenceKeys: Set<String> = [
        "disabled", "allowDNS", "allowLocalHost", "useAllowList", "currentProfile"
    ]

    // The caller must pin the Python interpreter and bundled helper in its
    // root-owned manifest. The helper itself accepts no runtime path arguments.
    static func loadFacts(pythonExecutable: URL, scriptURL: URL) throws -> LuLuFacts {
        guard pythonExecutable.isFileURL, scriptURL.isFileURL,
              pythonExecutable.path.hasPrefix("/"), scriptURL.path.hasPrefix("/") else {
            throw LuLuPolicyError.helperUnavailable
        }
        final class Output: @unchecked Sendable {
            let lock = NSLock()
            var bytes = Data()
            var failed = false
            func append(_ part: Data) -> Bool {
                lock.lock(); defer { lock.unlock() }
                guard bytes.count + part.count <= 4 * 1024 * 1024 else {
                    failed = true; return false
                }
                bytes.append(part)
                return true
            }
            func result() -> Data? {
                lock.lock(); defer { lock.unlock() }
                return failed ? nil : bytes
            }
        }
        let output = Output()
        let pipe = Pipe()
        let process = Process()
        process.executableURL = pythonExecutable
        process.arguments = ["-I", scriptURL.path]
        process.environment = ["PATH": "/usr/bin:/bin", "PYTHONNOUSERSITE": "1",
                               "PYTHONSAFEPATH": "1", "LC_ALL": "C", "HOME": "/var/empty"]
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        let finished = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in finished.signal() }
        do { try process.run() }
        catch { throw LuLuPolicyError.helperUnavailable }
        pipe.fileHandleForWriting.closeFile()
        let reader = DispatchGroup()
        reader.enter()
        DispatchQueue.global(qos: .utility).async {
            defer { reader.leave() }
            do {
                while let chunk = try pipe.fileHandleForReading.read(upToCount: 65_536),
                      !chunk.isEmpty {
                    if !output.append(chunk) {
                        if process.isRunning { process.terminate() }
                        break
                    }
                }
            } catch { output.lock.lock(); output.failed = true; output.lock.unlock() }
        }
        if finished.wait(timeout: .now() + 3) == .timedOut {
            if process.isRunning { process.terminate() }
            if finished.wait(timeout: .now() + 1) == .timedOut {
                if process.isRunning { Darwin.kill(process.processIdentifier, SIGKILL) }
                _ = finished.wait(timeout: .now() + 1)
            }
            throw LuLuPolicyError.helperUnavailable
        }
        guard reader.wait(timeout: .now() + 1) == .success,
              process.terminationStatus == 0,
              let bytes = output.result(), !bytes.isEmpty,
              let object = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              Set(object.keys) == Set(["schemaVersion", "home", "preferencesFileSHA256",
                                       "rulesFileSHA256", "preferences", "rules"]) else {
            throw LuLuPolicyError.helperOutputInvalid
        }
        do { return try JSONDecoder().decode(LuLuFacts.self, from: bytes) }
        catch { throw LuLuPolicyError.helperOutputInvalid }
    }

    private static func digest(_ value: String) -> String {
        SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
    }
    private static func validHash(_ value: String) -> Bool {
        value.count == 64 && value.utf8.allSatisfy {
            (48...57).contains($0) || (97...102).contains($0)
        }
    }

    // Python json.dumps(..., ensure_ascii=True) string quoting. All non-ASCII
    // scalars are escaped so sorting and digesting match the incumbent guard.
    private static func quote(_ text: String) -> String {
        var result = "\""
        for scalar in text.unicodeScalars {
            let n = scalar.value
            switch n {
            case 34: result += "\\\""
            case 92: result += "\\\\"
            case 8: result += "\\b"
            case 9: result += "\\t"
            case 10: result += "\\n"
            case 12: result += "\\f"
            case 13: result += "\\r"
            case 0..<32, 128...65535:
                result += String(format: "\\u%04x", n)
            case 65536...0x10ffff:
                let reduced = n - 65536
                result += String(format: "\\u%04x\\u%04x",
                                 0xd800 + reduced / 1024, 0xdc00 + reduced % 1024)
            default: result.unicodeScalars.append(scalar)
            }
        }
        return result + "\""
    }
    private static func serialized(_ atom: LuLuAtom) -> String {
        switch atom {
        case .null: return "null"
        case .bool(let item): return item ? "true" : "false"
        case .int(let item): return String(item)
        case .string(let item): return quote(item)
        }
    }
    private static func serialized(_ rule: LuLuRule) -> String {
        "{" + rule.fields.map { quote($0.0) + ": " + serialized($0.1) }.joined(separator: ", ") + "}"
    }
    static func legacyDigest(_ rules: [LuLuRule]) -> String {
        let ordered = rules.map(serialized).sorted()
        return digest("[" + ordered.joined(separator: ", ") + "]")
    }

    static func validate(facts: LuLuFacts, expectedHome: String,
                         expectedLegacyDigest: String) throws -> LuLuPolicyEvidence {
        guard facts.schemaVersion == 1, facts.home == expectedHome,
              expectedHome.hasPrefix("/"), !expectedHome.hasSuffix("/"),
              !expectedHome.contains("/../"),
              facts.preferences.keys.count == preferenceKeys.count,
              Set(facts.preferences.keys) == preferenceKeys else { throw LuLuPolicyError.wrongScope }
        guard validHash(facts.preferencesFileSHA256),
              validHash(facts.rulesFileSHA256), validHash(expectedLegacyDigest) else {
            throw LuLuPolicyError.sourceChanged
        }
        guard facts.preferences.values.allSatisfy(\.off) else {
            throw LuLuPolicyError.globalException
        }
        let roots = [claudeRoot, expectedHome + sunSuffix]
        let required = [claude, claudeRoot + "*", roots[1] + "*"]
        let entryPorts = [claude: "17897", claudeRoot + "*": "17897", roots[1] + "*": "17898"]
        for rule in facts.rules {
            guard rule.scope == .null else { throw LuLuPolicyError.unsupportedScope }
            guard rule.type == .int(3), rule.endpointHost == rule.endpointAddr else {
                throw LuLuPolicyError.metadataChanged
            }
            guard let path = rule.path.text,
                  path == claude || roots.contains(where: { path.hasPrefix($0) }),
                  rule.key.text != nil, rule.endpointAddr.text != nil,
                  rule.endpointPort.text != nil,
                  let action = rule.action.integer, action == 0 || action == 1,
                  rule.isEndpointAddrRegex.integer != nil,
                  rule.isDisabled.off else { throw LuLuPolicyError.malformedRule }
            guard rule.pid == .null, rule.expiration == .null else {
                throw LuLuPolicyError.temporaryRule
            }
            // Each application can reach only its own independently leased entry.
            if action == 1 && !(entryPorts[path] != nil &&
                                rule.endpointAddr.text == "127.0.0.1" &&
                                rule.endpointPort.text == entryPorts[path] &&
                                rule.isEndpointAddrRegex.integer == 0) {
                throw LuLuPolicyError.extraAllow
            }
        }
        for path in required {
            let scoped = facts.rules.filter { $0.path.text == path }
            guard scoped.contains(where: { $0.action.integer == 0 &&
                $0.endpointAddr.text == ".*" && $0.endpointPort.text == "*" &&
                $0.isEndpointAddrRegex.integer == 1 }) else {
                throw LuLuPolicyError.missingDeny(path)
            }
            guard scoped.contains(where: { $0.action.integer == 1 &&
                    $0.endpointAddr.text == "127.0.0.1" && $0.endpointPort.text == entryPorts[path] &&
                    $0.isEndpointAddrRegex.integer == 0 }) else {
                    throw LuLuPolicyError.missingAllow(path)
            }
        }
        let recomputed = legacyDigest(facts.rules)
        guard recomputed == expectedLegacyDigest else { throw LuLuPolicyError.legacyDigestChanged }
        return LuLuPolicyEvidence(legacyDigest: recomputed,
                                  selectedRuleCount: facts.rules.count,
                                  rulesFileSHA256: facts.rulesFileSHA256,
                                  preferencesFileSHA256: facts.preferencesFileSHA256)
    }
}
