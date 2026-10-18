import CryptoKit
import Darwin
import Foundation
import LegacyProcessShim

@main
struct ManagedLaunchCandidateTests {
    static func main() throws {
        guard CommandLine.arguments.count == 2 else { fatalError("fixture executable argument required") }
        let fixtureExecutable = CommandLine.arguments[1]
        let root = URL(fileURLWithPath: CommandLine.arguments[0])
            .deletingLastPathComponent().deletingLastPathComponent()
        let run = root.appendingPathComponent("managed-launch-fixture-\(UUID().uuidString.lowercased())",
                                              isDirectory: true)
        try FileManager.default.createDirectory(at: run, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: run) }

        let home = run.appendingPathComponent("home", isDirectory: true)
        let bin = home.appendingPathComponent("bin", isDirectory: true)
        let project = home.appendingPathComponent("project", isDirectory: true)
        let config = home.appendingPathComponent(".claude", isDirectory: true)
        let fixture = bin.appendingPathComponent("managed-fixture")
        let callback = home.appendingPathComponent("Applications/CCBaga-B.app/Contents/MacOS/Chromium")
        for directory in [home, bin, project, config, callback.deletingLastPathComponent()] {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        }
        try FileManager.default.copyItem(atPath: fixtureExecutable, toPath: fixture.path)
        try FileManager.default.copyItem(at: fixture, to: callback)
        try signFixture(fixture.path, identifier: "local.guard.managed-launch-fixture")
        try signFixture(callback.path, identifier: "ai.local.requirement-french.browser")
        try profilePinsOnlyGuardEgress()

        try sealedConfigurationRejectsUnsafeInputs(home: home.path, fixture: fixture.path,
                                                   callback: callback.path, project: project.path,
                                                   config: config.path)

        let secret = home.appendingPathComponent("sealed-secret.txt")
        try Data("fixture-only secret\n".utf8).write(to: secret)
        let parentMarker = home.appendingPathComponent("parent.marker")
        let childMarker = home.appendingPathComponent("child.marker")
        var descriptors: [Int32] = [0, 0]
        try expect(pipe(&descriptors) == 0, "could not create offline inherited-fd fixture")
        defer { close(descriptors[0]); close(descriptors[1]) }
        let leakedDescriptor = fcntl(descriptors[1], F_DUPFD, 4_000)
        try expect(leakedDescriptor >= 4_000, "could not create high-numbered inherited fd")
        _ = fcntl(leakedDescriptor, F_SETFD, 0)
        try expect(fcntl(leakedDescriptor, F_GETFD) >= 0, "inherited-fd fixture was not open in parent")
        let value = targetConfiguration(home: home.path, fixture: fixture.path, callback: callback.path,
                                        project: project.path, config: config.path,
                                        arguments: [secret.path, parentMarker.path, childMarker.path,
                                                    String(leakedDescriptor), "emit"])
        let bytes = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        let configuration = try ManagedLaunchConfiguration.decodeSealed(
            bytes, expectedSHA256: sha256(bytes), expectedHome: home.path)
        let coordinator = try ManagedLaunchCoordinator(configuration: configuration,
                                                        fixtureDeniedReadPath: secret.path)
        var gateOpen = true
        var outputPipe: [Int32] = [0, 0]
        try expect(pipe(&outputPipe) == 0, "could not create stdio inheritance fixture")
        var stdioOutput = fcntl(outputPipe[1], F_DUPFD, 5_000)
        try expect(stdioOutput >= 5_000, "could not allocate explicit stdio descriptor")
        defer {
            close(outputPipe[0])
            if stdioOutput >= 0 { close(stdioOutput) }
        }
        close(outputPipe[1])
        let receipt = try coordinator.start(
            targetID: "claude_code",
            stdio: ManagedLaunchStdio(input: STDIN_FILENO, output: stdioOutput,
                                      error: STDERR_FILENO),
            gateReadback: { gateOpen })
        close(stdioOutput)
        stdioOutput = -1
        try expect(receipt.pid == receipt.processGroupID, "launch did not own a new process group")
        try waitFor([parentMarker, childMarker])
        let parentText = try String(contentsOf: parentMarker, encoding: .utf8)
        let childText = try String(contentsOf: childMarker, encoding: .utf8)
        try expect(parentText.contains("parent=denied"), "sandbox did not deny parent sentinel read")
        try expect(childText.contains("child=denied"), "child did not inherit the Seatbelt restriction")
        try expect(parentText.contains("pgid=\(receipt.processGroupID)"), "parent escaped managed group")
        try expect(childText.contains("pgid=\(receipt.processGroupID)"), "child escaped managed group")
        var memberCount: Int32 = 0
        let groupReadback = lg_process_group_count(receipt.processGroupID, &memberCount)
        try expect(groupReadback == 0 && memberCount >= 2,
                   "owned process-group readback missed a fixture member")
        try expect(parentText.contains("proxy=http://127.0.0.1:17897"), "fixed proxy env missing")
        try expect(parentText.contains("browser=missing"),
                   "raw Chromium callback bypassed the managed browser handoff")
        try expect(parentText.contains("tmp=\(receipt.runtimeDirectory.path)/"), "private temp env missing")
        try expect(parentText.contains("fd=closed"), "managed spawn leaked a parent file descriptor")
        try expect(parentText.contains("privacy=cli_ok"),
                   "canonical CLI privacy patch did not reach child: \(parentText)")

        do {
            _ = try coordinator.stop(receipt, gateReadback: { true })
            throw FixtureFailure.assertion("stop accepted an open Guard gate")
        } catch ManagedLaunchError.gateStillOpen {}
        gateOpen = false
        let stopped = try coordinator.stop(receipt, gateReadback: { gateOpen })
        try expect(stopped.processGroupExited && !stopped.confirmedExited && stopped.remainingGroupMembers == 0,
                   "group stop did not confirm process exit")
        errno = 0
        try expect(kill(receipt.pid, 0) == -1 && errno == ESRCH, "leader still exists after readback")
        var captured = [UInt8](repeating: 0, count: 256)
        let capturedCount = captured.withUnsafeMutableBytes {
            Darwin.read(outputPipe[0], $0.baseAddress, $0.count)
        }
        try expect(capturedCount > 0 &&
                   String(decoding: captured.prefix(capturedCount), as: UTF8.self)
                    .contains("fixture-stdio-inherited"),
                   "standard output was not explicitly inherited")

        try mcpRootReceivesCanonicalPrivacy(home: home.path, fixture: fixture.path,
                                            callback: callback.path, project: project.path,
                                            config: config.path, secret: secret.path)
        try finalGateReadbackStopsBeforeSuccess(home: home.path, fixture: fixture.path, callback: callback.path,
                                               project: project.path, config: config.path)
        try browserRootDoesNotReceiveCLIEnvironment(home: home.path, fixture: fixture.path,
                                                   callback: callback.path, project: project.path,
                                                   config: config.path, secret: secret.path)
        print("managed-launch candidate: seal, inherited Seatbelt denial, fixed proxy, dedicated group and process-group cleanup passed; descendant cleanup remains unverified; no network socket was opened")
    }

    private static func targetConfiguration(home: String, fixture: String, callback: String,
                                            project: String, config: String,
                                            arguments: [String], targetID: String = "claude_code",
                                            executablePath: String? = nil,
                                            codeRequirement: String? = nil) -> [String: Any] {
        let target: [String: Any] = [
            "targetID": targetID,
            "executablePath": executablePath ?? fixture,
            "codeRequirement": codeRequirement ?? "identifier \"local.guard.managed-launch-fixture\"",
            "arguments": arguments,
            "workingDirectory": project,
            "configurationDirectory": config,
            "temporaryDirectoryRoot": home + "/.local/share/claude-network-guard/managed",
            "callbackBrowserPath": callback,
            "callbackBrowserCodeRequirement": "identifier \"ai.local.requirement-french.browser\""
        ]
        return ["schemaVersion": 1, "home": home, "proxyAddress": "127.0.0.1",
                "proxyPort": 17_897, "targets": [target]]
    }

    private static func sealedConfigurationRejectsUnsafeInputs(home: String, fixture: String,
                                                               callback: String,
                                                               project: String, config: String) throws {
        let valid = targetConfiguration(home: home, fixture: fixture, callback: callback,
                                        project: project,
                                        config: config, arguments: [])
        let validBytes = try JSONSerialization.data(withJSONObject: valid, options: [.sortedKeys])
        _ = try ManagedLaunchConfiguration.decodeSealed(validBytes, expectedSHA256: sha256(validBytes),
                                                        expectedHome: home)
        do {
            _ = try ManagedLaunchConfiguration.decodeSealed(validBytes, expectedSHA256: String(repeating: "0", count: 64),
                                                            expectedHome: home)
            throw FixtureFailure.assertion("seal mismatch accepted")
        } catch ManagedLaunchError.sealMismatch {}

        var sharedNode = valid
        var nodeTargets = sharedNode["targets"] as! [[String: Any]]
        nodeTargets[0]["executablePath"] = "/opt/homebrew/bin/node"
        sharedNode["targets"] = nodeTargets
        let nodeBytes = try JSONSerialization.data(withJSONObject: sharedNode, options: [.sortedKeys])
        do {
            _ = try ManagedLaunchConfiguration.decodeSealed(nodeBytes, expectedSHA256: sha256(nodeBytes),
                                                            expectedHome: home)
            throw FixtureFailure.assertion("shared Node runtime accepted as a managed root command")
        } catch ManagedLaunchError.malformedConfiguration {}

        var shellRoot = valid
        var shellTargets = shellRoot["targets"] as! [[String: Any]]
        shellTargets[0]["executablePath"] = "/bin/zsh"
        shellRoot["targets"] = shellTargets
        let shellBytes = try JSONSerialization.data(withJSONObject: shellRoot, options: [.sortedKeys])
        do {
            _ = try ManagedLaunchConfiguration.decodeSealed(shellBytes, expectedSHA256: sha256(shellBytes),
                                                            expectedHome: home)
            throw FixtureFailure.assertion("shell root command accepted")
        } catch ManagedLaunchError.malformedConfiguration {}

        var externalBrowser = valid
        var browserTargets = externalBrowser["targets"] as! [[String: Any]]
        browserTargets[0]["callbackBrowserPath"] = "/usr/bin/open"
        externalBrowser["targets"] = browserTargets
        let browserBytes = try JSONSerialization.data(withJSONObject: externalBrowser, options: [.sortedKeys])
        do {
            _ = try ManagedLaunchConfiguration.decodeSealed(browserBytes, expectedSHA256: sha256(browserBytes),
                                                            expectedHome: home)
            throw FixtureFailure.assertion("LaunchServices browser dispatcher accepted as callback browser")
        } catch ManagedLaunchError.malformedConfiguration {}
    }

    private static func finalGateReadbackStopsBeforeSuccess(home: String, fixture: String,
                                                            callback: String,
                                                            project: String, config: String) throws {
        let marker = home + "/cancelled.marker"
        let child = home + "/cancelled-child.marker"
        let secret = home + "/sealed-secret.txt"
        let value = targetConfiguration(home: home, fixture: fixture, callback: callback,
                                        project: project,
                                        config: config, arguments: [secret, marker, child, "500000", "silent"])
        let bytes = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        let configuration = try ManagedLaunchConfiguration.decodeSealed(
            bytes, expectedSHA256: sha256(bytes), expectedHome: home)
        let coordinator = try ManagedLaunchCoordinator(configuration: configuration,
                                                        fixtureDeniedReadPath: secret)
        var readbackCount = 0
        do {
            _ = try coordinator.start(targetID: "claude_code", gateReadback: {
                readbackCount += 1
                if readbackCount == 1 { return true }
                try waitFor([URL(fileURLWithPath: marker), URL(fileURLWithPath: child)])
                return false
            })
            throw FixtureFailure.assertion("start reported success after the final gate readback closed")
        } catch ManagedLaunchError.cleanupUnconfirmed {}
        try waitFor([URL(fileURLWithPath: marker), URL(fileURLWithPath: child)])
        let line = try String(contentsOfFile: marker, encoding: .utf8)
        let childLine = try String(contentsOfFile: child, encoding: .utf8)
        guard let raw = line.split(separator: " ").first(where: { $0.hasPrefix("pgid=") }),
              let pgid = pid_t(String(raw.dropFirst(5))),
              let childRaw = childLine.split(separator: " ").first(where: { $0.hasPrefix("pid=") }),
              let childPID = pid_t(String(childRaw.dropFirst(4))) else {
            throw FixtureFailure.assertion("could not read cancelled launch group id")
        }
        var initialCount: Int32 = 0
        try expect(lg_process_group_count(pgid, &initialCount) == 0 && initialCount > 0,
                   "candidate falsely cleaned a detached-capable descendant scope")
        // The candidate correctly returned cleanupUnconfirmed. The disposable
        // harness owns the exact child PID and removes it without a group kill.
        _ = kill(childPID, SIGTERM)
        let end = Date().addingTimeInterval(1)
        while Date() < end {
            var count: Int32 = -1
            if lg_process_group_count(pgid, &count) == 0 && count == 0 { return }
            Thread.sleep(forTimeInterval: 0.025)
        }
        throw FixtureFailure.assertion("final-readback cancellation left fixture group running")
    }

    private static func browserRootDoesNotReceiveCLIEnvironment(home: String, fixture: String,
                                                                 callback: String, project: String,
                                                                 config: String, secret: String) throws {
        let parent = home + "/browser-parent.marker"
        let child = home + "/browser-child.marker"
        let requirement = "identifier \"ai.local.requirement-french.browser\""
        let value = targetConfiguration(home: home, fixture: fixture, callback: callback,
                                        project: project, config: config,
                                        arguments: [secret, parent, child, "500000", "silent"],
                                        targetID: "ccbaga_browser", executablePath: callback,
                                        codeRequirement: requirement)
        let bytes = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        let configuration = try ManagedLaunchConfiguration.decodeSealed(
            bytes, expectedSHA256: sha256(bytes), expectedHome: home)
        let coordinator = try ManagedLaunchCoordinator(configuration: configuration,
                                                        fixtureDeniedReadPath: secret)
        let receipt = try coordinator.start(targetID: "ccbaga_browser", gateReadback: { true })
        try waitFor([URL(fileURLWithPath: parent), URL(fileURLWithPath: child)])
        let parentText = try String(contentsOfFile: parent, encoding: .utf8)
        try expect(parentText.contains("privacy=cli_absent"),
                   "CCBaga Browser inherited Claude Code telemetry variables")
        try expect(parentText.contains("browser=missing"),
                   "CCBaga Browser inherited the CLI callback-browser command")
        let stopped = try coordinator.stop(receipt, gateReadback: { false })
        try expect(stopped.processGroupExited && !stopped.confirmedExited && stopped.remainingGroupMembers == 0,
                   "CCBaga Browser fixture cleanup was not confirmed")
    }

    private static func mcpRootReceivesCanonicalPrivacy(home: String, fixture: String,
                                                        callback: String, project: String,
                                                        config: String, secret: String) throws {
        let parent = home + "/mcp-parent.marker"
        let child = home + "/mcp-child.marker"
        let value = targetConfiguration(home: home, fixture: fixture, callback: callback,
                                        project: project, config: config,
                                        arguments: [secret, parent, child, "500000", "silent"],
                                        targetID: "mcp")
        let bytes = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        let configuration = try ManagedLaunchConfiguration.decodeSealed(
            bytes, expectedSHA256: sha256(bytes), expectedHome: home)
        let coordinator = try ManagedLaunchCoordinator(configuration: configuration,
                                                        fixtureDeniedReadPath: secret)
        let receipt = try coordinator.start(targetID: "mcp", gateReadback: { true })
        try waitFor([URL(fileURLWithPath: parent), URL(fileURLWithPath: child)])
        let parentText = try String(contentsOfFile: parent, encoding: .utf8)
        try expect(parentText.contains("privacy=cli_ok"),
                   "MCP root did not receive the canonical CLI privacy patch")
        let stopped = try coordinator.stop(receipt, gateReadback: { false })
        try expect(stopped.processGroupExited && !stopped.confirmedExited && stopped.remainingGroupMembers == 0,
                   "MCP fixture cleanup was not confirmed")
    }

    private static func signFixture(_ path: String, identifier: String) throws {
        let signer = Process()
        signer.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        signer.arguments = ["--force", "--sign", "-", "--identifier", identifier, path]
        try signer.run()
        signer.waitUntilExit()
        try expect(signer.terminationStatus == 0, "could not ad-hoc sign disposable fixture")
    }

    private static func profilePinsOnlyGuardEgress() throws {
        let profile = ManagedLaunchProfile.render()
        for required in [
            "(deny network-outbound (require-not (remote tcp \"localhost:17897\")))",
            "(deny network-inbound)", "(deny network-bind)", "(deny lsopen)",
            "(deny appleevent-send)", "com.apple.coreservices.appleevents",
            "^com\\.apple\\.lsd"
        ] {
            try expect(profile.contains(required), "Seatbelt profile missing required restriction: \(required)")
        }
    }

    private static func waitFor(_ urls: [URL]) throws {
        let end = Date().addingTimeInterval(2)
        while Date() < end {
            if urls.allSatisfy({ FileManager.default.fileExists(atPath: $0.path) }) { return }
            Thread.sleep(forTimeInterval: 0.01)
        }
        throw FixtureFailure.assertion("fixture markers were not written")
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        guard condition() else { throw FixtureFailure.assertion(message) }
    }
}

enum FixtureFailure: Error {
    case assertion(String)
}
