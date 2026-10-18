import CryptoKit
import Darwin
import Foundation
import LegacyProcessShim
import Security

enum ManagedLaunchError: Error, Equatable {
    case malformedConfiguration, sealMismatch, unsupportedTarget
    case invalidPath, invalidSignature, sandboxUnavailable, profileWrite
    case invalidPrivacyPolicy, spawn(Int32), processIdentity, gateClosed, gateStillOpen, cleanupUnconfirmed
}

struct ManagedLaunchTarget: Codable, Equatable {
    let targetID: String
    let executablePath: String
    let codeRequirement: String
    let arguments: [String]
    let workingDirectory: String
    let configurationDirectory: String
    let temporaryDirectoryRoot: String
    let callbackBrowserPath: String
    let callbackBrowserCodeRequirement: String
}

struct ManagedLaunchConfiguration: Codable, Equatable {
    let schemaVersion: Int
    let home: String
    let proxyAddress: String
    let proxyPort: Int
    let targets: [ManagedLaunchTarget]

    var targetsByID: [String: ManagedLaunchTarget] {
        Dictionary(uniqueKeysWithValues: targets.map { ($0.targetID, $0) })
    }

    static func decodeSealed(_ data: Data, expectedSHA256: String,
                             expectedHome: String) throws -> Self {
        guard data.count <= 262_144, validHash(expectedSHA256),
              digest(data) == expectedSHA256 else { throw ManagedLaunchError.sealMismatch }
        let decoded: Any
        do { decoded = try JSONSerialization.jsonObject(with: data) }
        catch { throw ManagedLaunchError.malformedConfiguration }
        guard let root = decoded as? [String: Any],
              Set(root.keys) == Set(["schemaVersion", "home", "proxyAddress", "proxyPort", "targets"]),
              let rows = root["targets"] as? [[String: Any]],
              rows.count <= 3,
              rows.allSatisfy({ Set($0.keys) == Set([
                "targetID", "executablePath", "codeRequirement", "arguments",
                "workingDirectory", "configurationDirectory", "temporaryDirectoryRoot",
                "callbackBrowserPath", "callbackBrowserCodeRequirement"
              ]) }) else { throw ManagedLaunchError.malformedConfiguration }
        let value: Self
        do { value = try JSONDecoder().decode(Self.self, from: data) }
        catch { throw ManagedLaunchError.malformedConfiguration }
        guard value.schemaVersion == 1, value.home == expectedHome,
              Self.validPath(value.home), value.proxyAddress == "127.0.0.1",
              value.proxyPort == 17_897, !value.targets.isEmpty,
              Set(value.targets.map(\.targetID)).count == value.targets.count,
              value.targets.allSatisfy({ Self.valid($0, home: expectedHome) }) else {
            throw ManagedLaunchError.malformedConfiguration
        }
        return value
    }

    private static let knownTargets: Set<String> = ["claude_code", "mcp", "ccbaga_browser"]
    private static let sharedRuntimeNames = [
        "node", "bun", "deno", "python", "python3", "ruby", "perl",
        "sh", "bash", "zsh", "fish", "env", "open", "osascript"
    ]

    private static func valid(_ target: ManagedLaunchTarget, home: String) -> Bool {
        guard knownTargets.contains(target.targetID),
              validPath(target.executablePath), validPath(target.workingDirectory),
              validPath(target.configurationDirectory), validPath(target.temporaryDirectoryRoot),
              validPath(target.callbackBrowserPath),
              target.workingDirectory == "/" || target.workingDirectory.hasPrefix(home + "/"),
              target.configurationDirectory.hasPrefix(home + "/"),
              target.temporaryDirectoryRoot == home + "/.local/share/claude-network-guard/managed",
              target.arguments.count <= 128,
              target.arguments.reduce(0, { $0 + $1.utf8.count }) <= 8_192,
              target.arguments.allSatisfy({ !$0.contains("\0") }),
              validRequirement(target.codeRequirement),
              validRequirement(target.callbackBrowserCodeRequirement),
              target.callbackBrowserCodeRequirement.contains("ai.local.requirement-french.browser") else {
            return false
        }
        let name = URL(fileURLWithPath: target.executablePath).lastPathComponent.lowercased()
        let callbackSuffix = "/CCBaga-B.app/Contents/MacOS/Chromium"
        guard !sharedRuntimeNames.contains(name),
              !name.hasPrefix("node-"), !name.hasPrefix("python"),
              target.executablePath != "/usr/bin/sandbox-exec",
              target.callbackBrowserPath.hasSuffix(callbackSuffix),
              (target.callbackBrowserPath.hasPrefix("/Applications/") ||
               target.callbackBrowserPath.hasPrefix(home + "/Applications/")),
              target.targetID != "ccbaga_browser" ||
                (target.executablePath == target.callbackBrowserPath &&
                 target.codeRequirement.contains("ai.local.requirement-french.browser")) else {
            return false
        }
        return true
    }

    private static func validRequirement(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 2_048 && !value.contains("\0")
    }

    private static func validPath(_ value: String) -> Bool {
        value.hasPrefix("/") && value.count <= 4_096 && !value.contains("\0") &&
        !value.contains("//") &&
        !value.split(separator: "/").contains(where: { $0 == "." || $0 == ".." })
    }

    private static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func validHash(_ value: String) -> Bool {
        value.count == 64 && value.utf8.allSatisfy {
            (48...57).contains($0) || (97...102).contains($0)
        }
    }
}

enum ManagedLaunchProfile {
    static let proxyURL = "http://127.0.0.1:17897"

    static func render() -> String {
        """
        (version 1)
        (allow default)
        (deny network-outbound (require-not (remote tcp "localhost:17897")))
        (deny network-inbound)
        (deny network-bind)
        (deny lsopen)
        (deny appleevent-send)
        (deny mach-lookup (global-name "com.apple.coreservices.appleevents"))
        (deny mach-lookup (global-name-regex #"^com\\.apple\\.lsd(\\..*)?$"))
        """
    }

    #if MANAGED_LAUNCH_FIXTURE_TESTS
    static func fixtureProfile(denyingFileRead path: String) throws -> String {
        guard path.hasPrefix("/"), path.utf8.allSatisfy({
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) ||
            "/._-".utf8.contains($0)
        }) else { throw ManagedLaunchError.invalidPath }
        return render() + "\n(deny file-read-data (literal \"\(path)\"))\n"
    }
    #endif
}

struct ManagedLaunchReceipt {
    let targetID: String
    let pid: pid_t
    let processGroupID: pid_t
    let started: Date
    fileprivate let leader: lg_process
    fileprivate let codeRequirement: String
    let runtimeDirectory: URL
}

struct ManagedLaunchStopReceipt {
    let processGroupExited: Bool
    // Group membership cannot prove that a descendant did not call setsid().
    let descendantScopeVerified = false
    var confirmedExited: Bool { processGroupExited && descendantScopeVerified }
    let checkedAt: Date
    let remainingGroupMembers: Int
}

struct ManagedLaunchStdio {
    let input: Int32
    let output: Int32
    let error: Int32

    static let current = Self(input: STDIN_FILENO, output: STDOUT_FILENO,
                              error: STDERR_FILENO)
}

final class ManagedLaunchCoordinator {
    private let configuration: ManagedLaunchConfiguration
    private let fileManager = FileManager.default
    private let profileContents: String

    init(configuration: ManagedLaunchConfiguration) {
        self.configuration = configuration
        profileContents = ManagedLaunchProfile.render()
    }

    #if MANAGED_LAUNCH_FIXTURE_TESTS
    init(configuration: ManagedLaunchConfiguration, fixtureDeniedReadPath: String) throws {
        self.configuration = configuration
        profileContents = try ManagedLaunchProfile.fixtureProfile(denyingFileRead: fixtureDeniedReadPath)
    }
    #endif

    func start(targetID: String, stdio: ManagedLaunchStdio = .current,
               gateReadback: () throws -> Bool) throws -> ManagedLaunchReceipt {
        guard try gateReadback() else { throw ManagedLaunchError.gateClosed }
        guard let target = configuration.targetsByID[targetID] else {
            throw ManagedLaunchError.unsupportedTarget
        }
        guard fileManager.fileExists(atPath: "/usr/bin/sandbox-exec") else {
            throw ManagedLaunchError.sandboxUnavailable
        }
        try Self.requirePhysical(target.executablePath)
        try Self.requirePhysical(target.workingDirectory)
        try Self.requirePhysical(target.configurationDirectory)
        try Self.requireSigned(target.executablePath, target.codeRequirement)
        try Self.requirePhysical(target.callbackBrowserPath)
        try Self.requireSigned(target.callbackBrowserPath, target.callbackBrowserCodeRequirement)

        let runtimeDirectory = try Self.makeRuntimeDirectory(target.temporaryDirectoryRoot,
                                                              home: configuration.home)
        var preserveRuntimeDirectory = false
        do {
            let profile = runtimeDirectory.appendingPathComponent("profile.sb")
            try Self.writePrivate(Data(profileContents.utf8), to: profile)
            let environment = try Self.environment(home: configuration.home, target: target,
                                                   temporaryDirectory: runtimeDirectory.path)
            let arguments = ["/usr/bin/sandbox-exec", "-f", profile.path, "--",
                             target.executablePath] + target.arguments
            let pid = try Self.spawn(arguments: arguments, environment: environment,
                                     workingDirectory: target.workingDirectory, stdio: stdio)
            do {
                let leader = try Self.waitForLeader(pid, path: target.executablePath,
                                                    requirement: target.codeRequirement)
                guard try gateReadback() else { throw ManagedLaunchError.gateClosed }
                return ManagedLaunchReceipt(targetID: targetID, pid: pid, processGroupID: pid,
                                            started: Date(), leader: leader,
                                            codeRequirement: target.codeRequirement,
                                            runtimeDirectory: runtimeDirectory)
            } catch {
                _ = Self.stopUnverifiedGroup(pid)
                // A process-group readback cannot rule out a descendant that
                // called setsid(). Preserve diagnostics and require recovery.
                preserveRuntimeDirectory = true
                throw ManagedLaunchError.cleanupUnconfirmed
            }
        } catch {
            if !preserveRuntimeDirectory {
                try? FileManager.default.removeItem(at: runtimeDirectory)
            }
            throw error
        }
    }

    func stop(_ receipt: ManagedLaunchReceipt,
              gateReadback: () throws -> Bool,
              graceMilliseconds: UInt64 = 1_500) throws -> ManagedLaunchStopReceipt {
        guard try !gateReadback() else { throw ManagedLaunchError.gateStillOpen }
        var leader = receipt.leader
        let signal = lg_signal_process_group_if_same(&leader,
                                                     receipt.codeRequirement, SIGTERM)
        if signal != 0 && signal != ESRCH {
            throw ManagedLaunchError.cleanupUnconfirmed
        }
        let graceEnd = Date().addingTimeInterval(Double(graceMilliseconds) / 1_000)
        while Date() < graceEnd {
            let members = try Self.groupCount(receipt.processGroupID)
            _ = Self.reapIfExited(receipt.pid)
            if members == 0 {
                if Self.reapIfExited(receipt.pid) {
                    return ManagedLaunchStopReceipt(processGroupExited: true, checkedAt: Date(),
                                                    remainingGroupMembers: 0)
                }
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        let remaining = try Self.groupCount(receipt.processGroupID)
        if remaining > 0 {
            // Do not SIGKILL by numeric PGID: after the leader is reaped a
            // same-user process could reuse that ID. Stay in recovery instead.
            throw ManagedLaunchError.cleanupUnconfirmed
        }
        let hardEnd = Date().addingTimeInterval(1.5)
        while Date() < hardEnd {
            let members = try Self.groupCount(receipt.processGroupID)
            let reaped = Self.reapIfExited(receipt.pid)
            if members == 0 && reaped {
                return ManagedLaunchStopReceipt(processGroupExited: true, checkedAt: Date(),
                                                remainingGroupMembers: 0)
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        let finalCount = try Self.groupCount(receipt.processGroupID)
        guard finalCount == 0, Self.reapIfExited(receipt.pid) else {
            throw ManagedLaunchError.cleanupUnconfirmed
        }
        return ManagedLaunchStopReceipt(processGroupExited: true, checkedAt: Date(),
                                        remainingGroupMembers: 0)
    }

    private static func environment(home: String, target: ManagedLaunchTarget,
                                    temporaryDirectory: String) throws -> [String: String] {
        let cliTarget = target.targetID == "claude_code" || target.targetID == "mcp"
        let fixed = [
            "HOME": home,
            "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "en_US.UTF-8",
            "TMPDIR": temporaryDirectory + "/",
            "HTTP_PROXY": ManagedLaunchProfile.proxyURL,
            "HTTPS_PROXY": ManagedLaunchProfile.proxyURL,
            "http_proxy": ManagedLaunchProfile.proxyURL,
            "https_proxy": ManagedLaunchProfile.proxyURL,
            "NO_PROXY": "",
            "no_proxy": ""
        ]
        // Start from a fixed child environment. Host cloud credentials,
        // telemetry headers and unrelated developer secrets are not inherited.
        var environment: [String: String] = [:]
        environment.merge(fixed) { _, value in value }
        guard cliTarget else { return environment }
        environment["CLAUDE_CONFIG_DIR"] = target.configurationDirectory
        // A raw Chromium path would skip the selected Guard profile and
        // start-page session. Authentication stays unavailable until a
        // trusted browser handoff exists.
        environment.removeValue(forKey: "BROWSER")
        let values = ManagedPrivacyDefaults.cliEnvironment
        let removals = ManagedPrivacyDefaults.removedKeys
        let reserved = Set(fixed.keys).union(["CLAUDE_CONFIG_DIR", "BROWSER"])
        let valueKeys = Set(values.keys)
        let removeKeys = Set(removals)
        guard valueKeys.count == values.count, removeKeys.count == removals.count,
              valueKeys.isDisjoint(with: reserved), removeKeys.isDisjoint(with: reserved),
              valueKeys.isDisjoint(with: removeKeys),
              values.allSatisfy({ !$0.key.isEmpty && !$0.key.contains("=") &&
                                  !$0.key.contains("\0") && !$0.value.contains("\0") }),
              removals.allSatisfy({ !$0.isEmpty && !$0.contains("=") && !$0.contains("\0") }) else {
            throw ManagedLaunchError.invalidPrivacyPolicy
        }
        environment.merge(values) { _, canonical in canonical }
        for key in removals { environment.removeValue(forKey: key) }
        return environment
    }

    private static func spawn(arguments: [String], environment: [String: String],
                              workingDirectory: String, stdio: ManagedLaunchStdio) throws -> pid_t {
        let keys = environment.keys.sorted()
        let argvValues = arguments.map { strdup($0) }
        let envValues = keys.map { strdup("\($0)=\(environment[$0]!)") }
        defer {
            argvValues.forEach { free($0) }
            envValues.forEach { free($0) }
        }
        let argv: [UnsafePointer<CChar>?] = argvValues.map { UnsafePointer<CChar>($0!) }
        let envp: [UnsafePointer<CChar>?] = envValues.map { UnsafePointer<CChar>($0!) }
        var pid: pid_t = 0
        let code = argv.withUnsafeBufferPointer { argvBuffer in
            envp.withUnsafeBufferPointer { envBuffer in
                workingDirectory.withCString { cwd in
                    lg_spawn_group(arguments[0], argvBuffer.baseAddress, argvBuffer.count,
                                   envBuffer.baseAddress, envBuffer.count, cwd,
                                   stdio.input, stdio.output, stdio.error, &pid)
                }
            }
        }
        guard code == 0 else { throw ManagedLaunchError.spawn(code) }
        return pid
    }

    private static func waitForLeader(_ pid: pid_t, path: String,
                                      requirement: String) throws -> lg_process {
        let end = Date().addingTimeInterval(1.5)
        repeat {
            var leader = lg_process()
            let result = lg_process_snapshot(pid, &leader)
            if result == 0 {
                let executable = executablePath(leader)
                if executable == path && getpgid(pid) == pid &&
                    requirement.withCString({ lg_signature_matches(pid, $0) }) == 0 {
                    return leader
                }
                if executable != "/usr/bin/sandbox-exec" {
                    throw ManagedLaunchError.processIdentity
                }
            } else if result != ESRCH {
                throw ManagedLaunchError.processIdentity
            }
            Thread.sleep(forTimeInterval: 0.025)
        } while Date() < end
        throw ManagedLaunchError.processIdentity
    }

    private static func executablePath(_ record: lg_process) -> String {
        var path = record.path
        return withUnsafeBytes(of: &path) { bytes in
            String(decoding: bytes.prefix { $0 != 0 }, as: UTF8.self)
        }
    }

    private static func requirePhysical(_ path: String) throws {
        guard let resolved = realpath(path, nil) else { throw ManagedLaunchError.invalidPath }
        defer { free(resolved) }
        guard String(cString: resolved) == path else { throw ManagedLaunchError.invalidPath }
    }

    private static func requireSigned(_ path: String, _ expression: String) throws {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
              let code else { throw ManagedLaunchError.invalidSignature }
        var text: SecRequirement?
        guard SecRequirementCreateWithString(expression as CFString, [], &text) == errSecSuccess,
              let text,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), text) == errSecSuccess else {
            throw ManagedLaunchError.invalidSignature
        }
    }

    private static func makeRuntimeDirectory(_ root: String, home: String) throws -> URL {
        guard root == home + "/.local/share/claude-network-guard/managed" else {
            throw ManagedLaunchError.invalidPath
        }
        try requirePhysical(home)
        var current = home
        let components = root.dropFirst(home.count).split(separator: "/").map(String.init)
        for (index, component) in components.enumerated() {
            current = URL(fileURLWithPath: current, isDirectory: true)
                .appendingPathComponent(component, isDirectory: true).path
            let final = index == components.count - 1
            if mkdir(current, mode_t(S_IRWXU)) != 0 && errno != EEXIST {
                throw ManagedLaunchError.invalidPath
            }
            var info = stat()
            guard current.withCString({ lstat($0, &info) }) == 0,
                  (info.st_mode & S_IFMT) == S_IFDIR,
                  (info.st_mode & mode_t(0o022)) == 0,
                  info.st_uid == getuid(),
                  !final || (info.st_uid == getuid() && (info.st_mode & mode_t(0o077)) == 0) else {
                throw ManagedLaunchError.invalidPath
            }
        }
        let session = URL(fileURLWithPath: root, isDirectory: true)
            .appendingPathComponent(UUID().uuidString.lowercased(), isDirectory: true)
        guard session.path.withCString({ mkdir($0, mode_t(S_IRWXU)) }) == 0 else {
            throw ManagedLaunchError.invalidPath
        }
        return session
    }

    private static func writePrivate(_ data: Data, to url: URL) throws {
        let fd = url.path.withCString { open($0, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode_t(S_IRUSR | S_IWUSR)) }
        guard fd >= 0 else { throw ManagedLaunchError.profileWrite }
        defer { close(fd) }
        var offset = 0
        while offset < data.count {
            let written = data.withUnsafeBytes { raw in
                Darwin.write(fd, raw.baseAddress!.advanced(by: offset), data.count - offset)
            }
            if written < 0 && errno == EINTR { continue }
            guard written > 0 else { throw ManagedLaunchError.profileWrite }
            offset += written
        }
        guard fsync(fd) == 0 else { throw ManagedLaunchError.profileWrite }
    }

    private static func groupCount(_ pgid: pid_t) throws -> Int {
        var count: Int32 = 0
        let code = lg_process_group_count(pgid, &count)
        guard code == 0, count >= 0 else { throw ManagedLaunchError.cleanupUnconfirmed }
        return Int(count)
    }

    private static func reapIfExited(_ pid: pid_t) -> Bool {
        var status: Int32 = 0
        let result = waitpid(pid, &status, WNOHANG)
        if result == pid { return true }
        return result < 0 && errno == ECHILD
    }

    private static func stopUnverifiedGroup(_ pgid: pid_t) -> Bool {
        // The directly spawned leader is still our unreaped child, so its PID
        // cannot be reused here. Descendants are only considered clean after
        // the group independently becomes empty.
        let killed = kill(pgid, SIGKILL)
        guard killed == 0 || killed == ESRCH else { return false }
        let end = Date().addingTimeInterval(1.5)
        while Date() < end {
            if (try? groupCount(pgid)) == 0 && reapIfExited(pgid) {
                return true
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        return false
    }

    private static func removeRuntimeDirectory(_ url: URL) throws {
        guard url.path.hasSuffix(url.lastPathComponent),
              url.lastPathComponent.range(of: "^[a-f0-9-]{36}$", options: .regularExpression) != nil else {
            throw ManagedLaunchError.invalidPath
        }
        do { try FileManager.default.removeItem(at: url) }
        catch { throw ManagedLaunchError.cleanupUnconfirmed }
    }
}
