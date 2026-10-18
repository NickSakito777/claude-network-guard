import Foundation

@main private struct LuLuPolicyTargetBindingTests {
    private static let home = "/Users/fixture"
    private static let claude = "/Applications/Claude.app"
    private static let claudeContents = "/Applications/Claude.app/Contents/*"
    private static let adspower = home + "/Library/Application Support/adspower_global/cwd_global/*"

    private static func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
        if !condition() { fatalError(message) }
    }

    private static func rule(path: String, allow: Bool, entryPort: String = "17897") -> LuLuRule {
        let address = allow ? "127.0.0.1" : ".*"
        let port = allow ? entryPort : "*"
        return LuLuRule(key: .string("fixture-\(path)-\(allow)"),
                        path: .string(path),
                        endpointAddr: .string(address),
                        endpointPort: .string(port),
                        action: .int(allow ? 1 : 0),
                        isEndpointAddrRegex: .int(allow ? 0 : 1),
                        isDisabled: .bool(false),
                        pid: .null,
                        expiration: .null,
                        scope: .null,
                        type: .int(3),
                        endpointHost: .string(address))
    }

    private static func facts(adspowerAllow: Bool, browserPort: String = "17898") -> LuLuFacts {
        var rules = [rule(path: claude, allow: false), rule(path: claude, allow: true),
                     rule(path: claudeContents, allow: false),
                     rule(path: claudeContents, allow: true),
                     rule(path: adspower, allow: false)]
        if adspowerAllow { rules.append(rule(path: adspower, allow: true, entryPort: browserPort)) }
        return LuLuFacts(schemaVersion: 1, home: home,
                         preferencesFileSHA256: String(repeating: "a", count: 64),
                         rulesFileSHA256: String(repeating: "b", count: 64),
                         preferences: ["disabled": .bool(false), "allowDNS": .bool(false),
                                       "allowLocalHost": .bool(false), "useAllowList": .bool(false),
                                       "currentProfile": .string("")],
                         rules: rules)
    }

    static func main() {
        let separated = facts(adspowerAllow: true)
        do {
            _ = try LuLuPolicy.validate(facts: separated, expectedHome: home,
                expectedLegacyDigest: LuLuPolicy.legacyDigest(separated.rules))
        } catch { fatalError("Separate target endpoints should validate: \(error)") }
        for wrongPort in ["17897", "7896", "*"] {
            let unsafe = facts(adspowerAllow: true, browserPort: wrongPort)
            do {
                _ = try LuLuPolicy.validate(facts: unsafe, expectedHome: home,
                    expectedLegacyDigest: LuLuPolicy.legacyDigest(unsafe.rules))
                fatalError("SunBrowser must use only its dedicated endpoint")
            } catch LuLuPolicyError.extraAllow {}
            catch { fatalError("Unexpected policy error: \(error)") }
        }
        let missing = facts(adspowerAllow: false)
        do {
            _ = try LuLuPolicy.validate(facts: missing, expectedHome: home,
                expectedLegacyDigest: LuLuPolicy.legacyDigest(missing.rules))
            fatalError("Missing target-specific allow must remain unavailable")
        } catch LuLuPolicyError.missingAllow(adspower) {}
        catch { fatalError("Unexpected missing-allow error: \(error)") }
        print("LuLu separate-target policy fixtures passed")
        if CommandLine.arguments.count == 3 {
            do {
                let actual = try JSONDecoder().decode(LuLuFacts.self,
                    from: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1])))
                let manifest = try JSONSerialization.jsonObject(with:
                    Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[2]))) as! [String: Any]
                _ = try LuLuPolicy.validate(facts: actual, expectedHome: manifest["home"] as! String,
                    expectedLegacyDigest: manifest["firewallPolicySHA"] as! String)
                print("Prepared rule facts and manifest digest match the production Swift validator.")
            } catch { fatalError("Prepared policy failed: \(error)") }
        }
    }
}
