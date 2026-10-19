import Darwin
import Foundation

enum GateHelperProductionFixture {
    private struct Child {
        let pid: pid_t
        var control: Int32
        let claudeListenerPeer: Int32
        let sunbrowserListenerPeer: Int32
        let activeClientPeer: Int32
        let activeUpstreamPeer: Int32
        let pendingClientPeer: Int32
        let pendingUpstreamPeer: Int32
        private(set) var reaped = false

        mutating func closeControl() {
            if control >= 0 { close(control); control = -1 }
        }

        mutating func markReaped() { reaped = true }

        mutating func dispose() {
            closeControl()
            close(claudeListenerPeer)
            close(sunbrowserListenerPeer)
            close(activeClientPeer)
            close(activeUpstreamPeer)
            close(pendingClientPeer)
            close(pendingUpstreamPeer)
            if !reaped {
                _ = kill(pid, SIGKILL)
                var status: Int32 = 0
                _ = waitpid(pid, &status, 0)
                reaped = true
            }
        }
    }

    static func run(executable: String) -> Int32 {
        do {
            try verifyFixedPolicyAndLifecycle(executable: executable)
            try verifyHostEOFRevokesPreparedGate(executable: executable)
            try verifyMissedHeartbeatRevokesAndExits(executable: executable)
            try verifyDrainTimeoutExitsWithoutAcknowledgement(executable: executable)
            try verifyReplyBackpressureUsesOperationDeadline(executable: executable,
                                                               kind: .lock)
            try verifyReplyBackpressureUsesOperationDeadline(executable: executable,
                                                               kind: .revoke)
            print("Gate helper production protocol fixture passed")
            return 0
        } catch {
            fputs("Gate helper production protocol fixture failed: \(error)\n", stderr)
            return 1
        }
    }

    private static func verifyFixedPolicyAndLifecycle(executable: String) throws {
        var child = try spawnChild(executable: executable)
        defer { child.dispose() }
        let channel = try GateHelperChannel(descriptor: child.control)
        let session = try startSession(channel, childPID: child.pid)
        var sequence: UInt64 = 2

        try channel.send(message(session, generation: 0, sequence: sequence,
                                 kind: .initialize, hostProcess: currentProcess,
                                 policyVersion: GateHelperProductionPolicy.version &+ 1))
        let wrongPolicy = try receive(channel, "wrong-policy rejection")
        try require(wrongPolicy.kind == .rejected && wrongPolicy.reason == .policy,
                    "INIT must reject caller-selected policy versions")
        sequence += 1

        let wrongHost = GateHelperProcessIdentity(pid: getpid() + 1, uid: UInt32(getuid()))
        try channel.send(message(session, generation: 0, sequence: sequence,
                                 kind: .initialize, hostProcess: wrongHost,
                                 policyVersion: GateHelperProductionPolicy.version))
        let wrongPeer = try receive(channel, "wrong-host rejection")
        try require(wrongPeer.kind == .rejected && wrongPeer.reason == .peer,
                    "INIT must bind to the inherited socketpair's direct host process")
        sequence += 1

        try channel.send(message(session, generation: 0, sequence: sequence,
                                 kind: .initialize, hostProcess: currentProcess,
                                 policyVersion: GateHelperProductionPolicy.version))
        let initialized = try receive(channel, "INITIALIZED")
        try require(initialized.kind == .initialized && initialized.generation == 0 &&
                    initialized.targetSnapshots?.count == 2 &&
                    initialized.targetSnapshots?.allSatisfy({ !$0.snapshot.bound && !$0.snapshot.open }) == true,
                    "INIT must allocate only the two compiled-in inert targets")
        sequence += 1

        try channel.send(message(session, generation: 0, sequence: sequence, kind: .heartbeat))
        let heartbeat = try receive(channel, "host heartbeat")
        try require(heartbeat.kind == .alive && heartbeat.generation == 0 &&
                    heartbeat.targetSnapshots?.count == 2,
                    "heartbeat must confirm the helper session without changing Gate state")
        sequence += 1

        try channel.send(message(session, generation: 0, sequence: sequence, kind: .prepare))
        let prepared = try receive(channel, "PREPARED")
        try require(prepared.kind == .prepared && prepared.targetSnapshots?.count == 2 &&
                    prepared.targetSnapshots?.allSatisfy({
                        $0.snapshot.bound && !$0.snapshot.open &&
                        $0.snapshot.activePairs == 0 && $0.snapshot.pending == 0
                    }) == true,
                    "PREPARE must bind both fixture Unix endpoints in a closed state")
        sequence += 1

        try channel.send(message(session, generation: 1, sequence: sequence,
                                 kind: .open, target: nil))
        let missingTarget = try receive(channel, "missing target rejection")
        try require(missingTarget.kind == .rejected && missingTarget.reason == .target,
                    "OPEN must name one fixed target enum")
        sequence += 1

        try channel.send(message(session, generation: 1, sequence: sequence,
                                 kind: .open, target: .claude))
        let claudeOpen = try receive(channel, "Claude OPEN")
        try require(claudeOpen.kind == .opened && target(.claude, in: claudeOpen)?.open == true &&
                    target(.sunbrowser, in: claudeOpen)?.open == false &&
                    target(.claude, in: claudeOpen)?.generation == 1,
                    "OPEN must grant only the selected compiled-in target")
        sequence += 1

        try channel.send(message(session, generation: 0, sequence: sequence, kind: .renew))
        let staleRenew = try receive(channel, "stale generation rejection")
        try require(staleRenew.kind == .rejected && staleRenew.reason == .generation,
                    "RENEW must reject a stale generation")
        sequence += 1

        try channel.send(message(session, generation: 2, sequence: sequence,
                                 kind: .open, target: .sunbrowser))
        let sunbrowserOpen = try receive(channel, "SunBrowser OPEN")
        try require(sunbrowserOpen.kind == .opened &&
                    sunbrowserOpen.targetSnapshots?.allSatisfy({
                        $0.snapshot.open && $0.snapshot.generation == 2
                    }) == true,
                    "opening the second target must advance the generation of all open targets")
        sequence += 1

        try channel.send(message(session, generation: 2, sequence: sequence, kind: .renew))
        let renewed = try receive(channel, "RENEW")
        try require(renewed.kind == .renewed && renewed.targetSnapshots?.allSatisfy({
            $0.snapshot.open && $0.snapshot.generation == 2
        }) == true, "RENEW must extend only the current generation under the fixed lease limit")
        sequence += 1

        try channel.send(message(session, generation: 2, sequence: sequence,
                                 kind: .fixtureSeedActivity))
        let seeded = try receive(channel, "active and pending fixture slots")
        try require(seeded.kind == .fixtureSeeded &&
                    target(.claude, in: seeded)?.activePairs == 1 &&
                    target(.sunbrowser, in: seeded)?.pending == 1,
                    "fixture must seed one Claude relay pair and one SunBrowser pending slot")
        sequence += 1

        try channel.send(message(session, generation: 2, sequence: sequence,
                                 kind: .fixtureHoldDrain))
        let held = try receive(channel, "held drain barrier")
        try require(held.kind == .fixtureHeld, "fixture must hold Claude drain before LOCK")
        sequence += 1

        let lockSequence = sequence
        try channel.send(message(session, generation: 2, sequence: lockSequence, kind: .lock))
        try require(!readable(child.control, timeout: 100),
                    "LOCK must wait for both Gates to drain before acknowledging")
        sequence += 1

        let lockedBeforeDrain = try waitForBothGatesClosed(
            channel, session: session, generation: 2, sequence: &sequence,
            label: "dual-Gate readback before drain release")
        try require(target(.sunbrowser, in: lockedBeforeDrain)?.pending == 1,
                    "LOCK must close both targets before waiting on the held Claude drain")

        try channel.send(message(session, generation: 2, sequence: sequence,
                                 kind: .fixtureReleaseDrain))
        let released = try receive(channel, "released fixture drain")
        try require(released.kind == .fixtureDrainReleased,
                    "fixture release must complete pending work and release the drain barrier")
        sequence += 1
        let locked = try receive(channel, "LOCK after both Gates drain")
        try require(locked.kind == .locked && locked.sequence == lockSequence &&
                    locked.targetSnapshots?.allSatisfy({
                        $0.snapshot.bound && !$0.snapshot.open &&
                        $0.snapshot.activePairs == 0 && $0.snapshot.pending == 0
                    }) == true,
                    "LOCK must confirm both listeners bound and all relay/pending slots empty")
        try expectEOF(child.activeClientPeer, "active client after LOCK")
        try expectEOF(child.activeUpstreamPeer, "active upstream after LOCK")
        try expectEOF(child.pendingClientPeer, "pending client after LOCK")
        try expectEOF(child.pendingUpstreamPeer, "pending upstream after LOCK")
        try require(!readable(child.claudeListenerPeer, timeout: 50) &&
                    !readable(child.sunbrowserListenerPeer, timeout: 50),
                    "LOCK must not revoke listener sockets")

        try channel.send(message(session, generation: 2, sequence: sequence, kind: .revoke))
        let revoked = try receive(channel, "REVOKE")
        try require(revoked.kind == .revoked && revoked.targetSnapshots?.allSatisfy({
            !$0.snapshot.bound && !$0.snapshot.open &&
            $0.snapshot.activePairs == 0 && $0.snapshot.pending == 0
        }) == true, "REVOKE must close both listeners and report a final empty snapshot")
        try waitForExit(&child, expectedExitCode: 0)
        try expectEOF(child.claudeListenerPeer, "Claude fixture listener after revoke")
        try expectEOF(child.sunbrowserListenerPeer, "SunBrowser fixture listener after revoke")
    }

    private static func verifyHostEOFRevokesPreparedGate(executable: String) throws {
        var child = try spawnChild(executable: executable)
        defer { child.dispose() }
        let channel = try GateHelperChannel(descriptor: child.control)
        let session = try startSession(channel, childPID: child.pid)
        try channel.send(message(session, generation: 0, sequence: 2,
                                 kind: .initialize, hostProcess: currentProcess,
                                 policyVersion: GateHelperProductionPolicy.version))
        let initialized = try receive(channel, "INITIALIZED after EOF test")
        try require(initialized.kind == .initialized, "initialize host EOF fixture")
        try channel.send(message(session, generation: 0, sequence: 3, kind: .prepare))
        let prepared = try receive(channel, "PREPARED before EOF")
        try require(prepared.kind == .prepared, "prepare host EOF fixture using only Unix sockets")
        try channel.send(message(session, generation: 1, sequence: 4,
                                 kind: .open, target: .claude))
        let opened = try receive(channel, "OPEN before EOF")
        try require(opened.kind == .opened, "open fixture Gate before host EOF")
        child.closeControl()
        try waitForExit(&child, expectedExitCode: 0)
        try expectEOF(child.claudeListenerPeer, "Claude fixture listener after host EOF")
        try expectEOF(child.sunbrowserListenerPeer, "SunBrowser fixture listener after host EOF")
    }

    private static func verifyMissedHeartbeatRevokesAndExits(executable: String) throws {
        var child = try spawnChild(executable: executable)
        defer { child.dispose() }
        let channel = try GateHelperChannel(descriptor: child.control)
        let session = try startSession(channel, childPID: child.pid)
        try channel.send(message(session, generation: 0, sequence: 2,
                                 kind: .initialize, hostProcess: currentProcess,
                                 policyVersion: GateHelperProductionPolicy.version))
        let initialized = try receive(channel, "watchdog INITIALIZED")
        try require(initialized.kind == .initialized, "watchdog fixture initializes")
        try channel.send(message(session, generation: 0, sequence: 3, kind: .prepare))
        let prepared = try receive(channel, "watchdog PREPARED")
        try require(prepared.kind == .prepared, "watchdog fixture prepares closed listeners")
        try channel.send(message(session, generation: 1, sequence: 4,
                                 kind: .open, target: .claude))
        let opened = try receive(channel, "watchdog OPEN")
        try require(opened.kind == .opened && target(.claude, in: opened)?.open == true,
                    "watchdog fixture opens only its Claude endpoint")

        let timeout = Double(GateHelperProductionPolicy.leaseNanoseconds) / 1_000_000_000 + 3
        try waitForExit(&child, expectedExitCode: 0, timeoutSeconds: timeout)
        try expectEOF(child.control, "control after missed host heartbeat")
        try expectEOF(child.claudeListenerPeer, "Claude listener after missed host heartbeat")
        try expectEOF(child.sunbrowserListenerPeer, "SunBrowser listener after missed host heartbeat")
    }

    private static func verifyDrainTimeoutExitsWithoutAcknowledgement(executable: String) throws {
        var child = try spawnChild(executable: executable)
        defer { child.dispose() }
        let channel = try GateHelperChannel(descriptor: child.control)
        let session = try startSession(channel, childPID: child.pid)
        var sequence: UInt64 = 2
        try channel.send(message(session, generation: 0, sequence: sequence,
                                 kind: .initialize, hostProcess: currentProcess,
                                 policyVersion: GateHelperProductionPolicy.version))
        let initialized = try receive(channel, "timeout fixture INITIALIZED")
        try require(initialized.kind == .initialized, "timeout fixture must initialize")
        sequence += 1
        try channel.send(message(session, generation: 0, sequence: sequence, kind: .prepare))
        let prepared = try receive(channel, "timeout fixture PREPARED")
        try require(prepared.kind == .prepared,
                    "timeout fixture must prepare both Unix listeners")
        sequence += 1
        try channel.send(message(session, generation: 1, sequence: sequence,
                                 kind: .open, target: .claude))
        let claudeOpen = try receive(channel, "timeout fixture Claude OPEN")
        try require(claudeOpen.kind == .opened, "timeout fixture must open Claude")
        sequence += 1
        try channel.send(message(session, generation: 2, sequence: sequence,
                                 kind: .open, target: .sunbrowser))
        let sunbrowserOpen = try receive(channel, "timeout fixture SunBrowser OPEN")
        try require(sunbrowserOpen.kind == .opened, "timeout fixture must open SunBrowser")
        sequence += 1
        try channel.send(message(session, generation: 2, sequence: sequence,
                                 kind: .fixtureSeedActivity))
        let seeded = try receive(channel, "timeout fixture active/pending seed")
        try require(seeded.kind == .fixtureSeeded,
                    "timeout fixture must install active and pending Unix socketpairs")
        sequence += 1
        try channel.send(message(session, generation: 2, sequence: sequence,
                                 kind: .fixtureHoldDrain))
        let held = try receive(channel, "timeout fixture held drain")
        try require(held.kind == .fixtureHeld,
                    "timeout fixture must hold the native drain barrier")
        sequence += 1
        let lockStartedAt = DispatchTime.now().uptimeNanoseconds
        try channel.send(message(session, generation: 2, sequence: sequence, kind: .lock))
        try require(!readable(child.control, timeout: 100),
                    "timed-out LOCK must not be acknowledged while drain is held")
        sequence += 1
        let status = try waitForBothGatesClosed(
            channel, session: session, generation: 2, sequence: &sequence,
            label: "timeout fixture fail-closed readback")
        try require(target(.sunbrowser, in: status)?.pending == 1,
                    "both Gate permissions must close before the bounded drain wait")
        let partialPrefix: [UInt8] = [0, 0]
        let sent = partialPrefix.withUnsafeBytes {
            send(child.control, $0.baseAddress!, $0.count, 0)
        }
        try require(sent == partialPrefix.count,
                    "partial control frame must not extend the LOCK deadline")

        let timeoutSeconds = Double(GateHelperProductionPolicy.terminationTimeoutNanoseconds) /
            1_000_000_000 + 2
        try waitForExit(&child, expectedExitCode: GateHelperProductionPolicy.timeoutExitCode,
                        timeoutSeconds: timeoutSeconds)
        let elapsed = DispatchTime.now().uptimeNanoseconds - lockStartedAt
        try require(elapsed <= GateHelperProductionPolicy.terminationTimeoutNanoseconds + 1_000_000_000,
                    "LOCK timeout must cover partial control input and end within one bounded deadline")
        try expectEOF(child.control, "control after bounded LOCK timeout")
        try expectEOF(child.claudeListenerPeer, "Claude listener after timeout")
        try expectEOF(child.sunbrowserListenerPeer, "SunBrowser listener after timeout")
        try expectEOF(child.activeClientPeer, "active client after timeout")
        try expectEOF(child.activeUpstreamPeer, "active upstream after timeout")
        try expectEOF(child.pendingClientPeer, "pending client after timeout")
        try expectEOF(child.pendingUpstreamPeer, "pending upstream after timeout")
    }

    private static func verifyReplyBackpressureUsesOperationDeadline(
        executable: String, kind: GateHelperKind
    ) throws {
        let operation = kind.rawValue.uppercased()
        var child = try spawnChild(executable: executable)
        defer { child.dispose() }
        let channel = try GateHelperChannel(descriptor: child.control)
        let session = try startSession(channel, childPID: child.pid)
        try channel.send(message(session, generation: 0, sequence: 2,
                                 kind: .initialize, hostProcess: currentProcess,
                                 policyVersion: GateHelperProductionPolicy.version))
        let initialized = try receive(channel, "backpressure INITIALIZED")
        try require(initialized.kind == .initialized, "backpressure fixture initializes")
        try channel.send(message(session, generation: 0, sequence: 3, kind: .prepare))
        let prepared = try receive(channel, "backpressure PREPARED")
        try require(prepared.kind == .prepared, "backpressure fixture prepares Unix endpoints")

        try channel.send(message(session, generation: 0, sequence: 4,
                                 kind: .fixtureFillOutputBuffer))
        try require(readable(child.control, timeout: 1_500),
                    "fixture must fill the helper-to-host socket before \(operation)")
        let startedAt = DispatchTime.now().uptimeNanoseconds
        try channel.send(message(session, generation: 0, sequence: 5, kind: kind))
        let timeoutSeconds = Double(GateHelperProductionPolicy.terminationTimeoutNanoseconds) /
            1_000_000_000 + 2
        try waitForExit(&child, expectedExitCode: GateHelperProductionPolicy.timeoutExitCode,
                        timeoutSeconds: timeoutSeconds)
        let elapsed = DispatchTime.now().uptimeNanoseconds - startedAt
        try require(elapsed >= GateHelperProductionPolicy.terminationTimeoutNanoseconds - 500_000_000 &&
                    elapsed <= GateHelperProductionPolicy.terminationTimeoutNanoseconds + 1_000_000_000,
                    "\(operation) reply backpressure must end at the operation deadline")

        let output = try drainUntilEOF(child.control)
        try require(!output.isEmpty && output.allSatisfy { $0 == 0xA5 },
                    "a timed-out \(operation) acknowledgement must not be appended to the full socket")
        try expectEOF(child.claudeListenerPeer, "Claude listener after \(operation) reply timeout")
        try expectEOF(child.sunbrowserListenerPeer, "SunBrowser listener after \(operation) reply timeout")
    }

    private static func spawnChild(executable: String) throws -> Child {
        let control = try socketPair()
        let claudeListener = try socketPair()
        let sunbrowserListener = try socketPair()
        let activeClient = try socketPair()
        let activeUpstream = try socketPair()
        let pendingClient = try socketPair()
        let pendingUpstream = try socketPair()
        let sentinel = try socketPair()
        var parentDescriptors = [control[0], control[1], claudeListener[0], claudeListener[1],
                                 sunbrowserListener[0], sunbrowserListener[1],
                                 activeClient[0], activeClient[1], activeUpstream[0], activeUpstream[1],
                                 pendingClient[0], pendingClient[1], pendingUpstream[0], pendingUpstream[1],
                                 sentinel[0], sentinel[1]]
        var sources: [Int32] = []
        do {
            let sentinelSource = try duplicateDescriptor(sentinel[0], minimum: 128)
            sources.append(sentinelSource)
            let childEnds = [control[1], claudeListener[1], sunbrowserListener[1],
                             activeClient[1], activeUpstream[1],
                             pendingClient[1], pendingUpstream[1]]
            for fd in childEnds { sources.append(try duplicateDescriptor(fd, minimum: 256)) }
            for fd in childEnds { close(fd) }
            parentDescriptors.removeAll { childEnds.contains($0) }

            var actions: posix_spawn_file_actions_t?
            try require(posix_spawn_file_actions_init(&actions) == 0,
                        "initialize production fixture spawn actions")
            defer { posix_spawn_file_actions_destroy(&actions) }
            for (source, target) in zip(sources.dropFirst(), [3, 4, 5, 6, 7, 8, 9]) {
                try require(posix_spawn_file_actions_adddup2(&actions, source, Int32(target)) == 0,
                            "whitelist fixture control and listener endpoints")
                try require(posix_spawn_file_actions_addclose(&actions, source) == 0,
                            "close fixture source descriptor after dup")
            }
            var attributes: posix_spawnattr_t?
            try require(posix_spawnattr_init(&attributes) == 0,
                        "initialize production fixture spawn attributes")
            defer { posix_spawnattr_destroy(&attributes) }
            try require(posix_spawnattr_setflags(&attributes,
                                                 Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)) == 0,
                        "enable close-on-exec default for production helper fixture")

            let arguments = [executable, "--production-fixture-child", "3", "4", "5",
                             String(sentinelSource), "6", "7", "8", "9"]
            let cArguments = arguments.map { strdup($0) }
            defer { cArguments.forEach { free($0) } }
            var argv = cArguments + [nil]
            var emptyEnvironment: [UnsafeMutablePointer<CChar>?] = [nil]
            var pid: pid_t = -1
            let result = executable.withCString { path in
                argv.withUnsafeMutableBufferPointer { argumentBuffer in
                    emptyEnvironment.withUnsafeMutableBufferPointer { environmentBuffer in
                        posix_spawn(&pid, path, &actions, &attributes,
                                    argumentBuffer.baseAddress!, environmentBuffer.baseAddress!)
                    }
                }
            }
            try require(result == 0 && pid > 0,
                        "spawn dedicated production protocol fixture: \(result)")
            for fd in sources { close(fd) }
            close(sentinel[0]); close(sentinel[1])
            parentDescriptors.removeAll { $0 == sentinel[0] || $0 == sentinel[1] }
            return Child(pid: pid, control: control[0],
                         claudeListenerPeer: claudeListener[0],
                         sunbrowserListenerPeer: sunbrowserListener[0],
                         activeClientPeer: activeClient[0],
                         activeUpstreamPeer: activeUpstream[0],
                         pendingClientPeer: pendingClient[0],
                         pendingUpstreamPeer: pendingUpstream[0])
        } catch {
            for fd in parentDescriptors { close(fd) }
            for fd in sources { close(fd) }
            throw error
        }
    }

    private static func startSession(_ channel: GateHelperChannel, childPID: pid_t) throws
        -> (nonce: [UInt8], epoch: UInt64) {
        let nonce = (0..<32).map { _ in UInt8.random(in: UInt8.min...UInt8.max) }
        let epoch = UInt64.random(in: 1...UInt64.max)
        try channel.send(GateHelperMessage(version: 1, nonce: nonce, epoch: epoch,
                                           generation: 0, sequence: 1, kind: .hello))
        let ready = try receive(channel, "READY")
        try require(ready.kind == .ready && ready.sequence == 1 &&
                    ready.nonce == nonce && ready.epoch == epoch &&
                    ready.helperProcess == GateHelperProcessIdentity(
                        pid: childPID, uid: UInt32(getuid())),
                    "READY identity must match the host's posix_spawn receipt")
        return (nonce, epoch)
    }

    private static var currentProcess: GateHelperProcessIdentity {
        GateHelperProcessIdentity(pid: getpid(), uid: UInt32(getuid()))
    }

    private static func message(_ session: (nonce: [UInt8], epoch: UInt64),
                                generation: UInt64, sequence: UInt64,
                                kind: GateHelperKind,
                                target: GateHelperTarget? = nil,
                                hostProcess: GateHelperProcessIdentity? = nil,
                                policyVersion: UInt16? = nil) -> GateHelperMessage {
        GateHelperMessage(version: 1, nonce: session.nonce, epoch: session.epoch,
                          generation: generation, sequence: sequence, kind: kind,
                          target: target, hostProcess: hostProcess,
                          policyVersion: policyVersion)
    }

    private static func target(_ target: GateHelperTarget,
                               in message: GateHelperMessage) -> GateHelperSnapshot? {
        message.targetSnapshots?.first(where: { $0.target == target })?.snapshot
    }

    private static func waitForBothGatesClosed(
        _ channel: GateHelperChannel,
        session: (nonce: [UInt8], epoch: UInt64),
        generation: UInt64,
        sequence: inout UInt64,
        label: String
    ) throws -> GateHelperMessage {
        let deadline = Date().addingTimeInterval(1)
        while Date() < deadline {
            try channel.send(message(session, generation: generation, sequence: sequence,
                                     kind: .fixtureStatus))
            let status = try receive(channel, label)
            sequence += 1
            if status.kind == .fixtureSnapshot &&
               target(.claude, in: status)?.open == false &&
               target(.sunbrowser, in: status)?.open == false {
                return status
            }
            usleep(10_000)
        }
        throw FixtureFailure.message("both Gate permissions did not close before the drain wait")
    }

    private static func socketPair() throws -> [Int32] {
        var descriptors: [Int32] = [-1, -1]
        let result = descriptors.withUnsafeMutableBufferPointer {
            socketpair(AF_UNIX, SOCK_STREAM, 0, $0.baseAddress!)
        }
        try require(result == 0, "create fixture Unix socketpair: \(errno)")
        for fd in descriptors {
            var noSignal: Int32 = 1
            try require(setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal,
                                   socklen_t(MemoryLayout<Int32>.size)) == 0,
                        "disable SIGPIPE on fixture socket")
        }
        return descriptors
    }

    private static func duplicateDescriptor(_ descriptor: Int32, minimum: Int32) throws -> Int32 {
        let copy = fcntl(descriptor, F_DUPFD_CLOEXEC, minimum)
        try require(copy >= minimum, "move fixture descriptor above the whitelist")
        return copy
    }

    private static func receive(_ channel: GateHelperChannel, _ label: String) throws
        -> GateHelperMessage {
        do { return try channel.receive() }
        catch { throw FixtureFailure.message("\(label): \(error)") }
    }

    private static func expectEOF(_ descriptor: Int32, _ label: String) throws {
        try require(readable(descriptor, timeout: 2_500), "wait for \(label)")
        var byte: UInt8 = 0
        let count = recv(descriptor, &byte, 1, 0)
        try require(count == 0, "\(label) must be closed, got \(count)")
    }

    private static func readable(_ descriptor: Int32, timeout: Int32) -> Bool {
        var event = pollfd(fd: descriptor, events: Int16(POLLIN | POLLHUP), revents: 0)
        return poll(&event, 1, timeout) == 1
    }

    private static func drainUntilEOF(_ descriptor: Int32) throws -> [UInt8] {
        var output: [UInt8] = []
        var buffer = [UInt8](repeating: 0, count: 8_192)
        while true {
            let count = buffer.withUnsafeMutableBytes {
                recv(descriptor, $0.baseAddress, $0.count, 0)
            }
            if count > 0 {
                output.append(contentsOf: buffer.prefix(count))
                continue
            }
            if count == 0 { return output }
            if errno == EINTR { continue }
            throw FixtureFailure.message("drain helper control output: \(errno)")
        }
    }

    private static func waitForExit(_ child: inout Child, expectedExitCode: Int32,
                                    timeoutSeconds: TimeInterval = 4) throws {
        let timeoutNanoseconds = UInt64(timeoutSeconds * 1_000_000_000)
        let deadline = DispatchTime.now().uptimeNanoseconds + timeoutNanoseconds
        while DispatchTime.now().uptimeNanoseconds < deadline {
            var status: Int32 = 0
            let result = waitpid(child.pid, &status, WNOHANG)
            if result == child.pid {
                child.markReaped()
                try require((status & 0x7f) == 0 && ((status >> 8) & 0xff) == expectedExitCode,
                            "helper fixture exit status \(status), expected \(expectedExitCode)")
                return
            }
            if result < 0 && errno != EINTR { throw FixtureFailure.message("waitpid: \(errno)") }
            usleep(10_000)
        }
        throw FixtureFailure.message("helper fixture did not exit before deadline")
    }

    private static func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        guard condition() else { throw FixtureFailure.message(message) }
    }
}

private enum FixtureFailure: Error, CustomStringConvertible {
    case message(String)
    var description: String { if case .message(let value) = self { return value }; return "fixture failure" }
}
