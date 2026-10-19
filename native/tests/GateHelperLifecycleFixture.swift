import Darwin
import Foundation

enum GateHelperLifecycleFixture {
    private static let timeoutMillis: Int32 = 4_000

    private final class Child {
        let pid: pid_t
        var control: Int32
        let listenerPeer: Int32
        let activeClientPeer: Int32
        let activeUpstreamPeer: Int32
        let pendingClientPeer: Int32
        let pendingUpstreamPeer: Int32
        private(set) var reaped = false

        init(pid: pid_t, control: Int32, listenerPeer: Int32,
             activeClientPeer: Int32, activeUpstreamPeer: Int32,
             pendingClientPeer: Int32, pendingUpstreamPeer: Int32) {
            self.pid = pid
            self.control = control
            self.listenerPeer = listenerPeer
            self.activeClientPeer = activeClientPeer
            self.activeUpstreamPeer = activeUpstreamPeer
            self.pendingClientPeer = pendingClientPeer
            self.pendingUpstreamPeer = pendingUpstreamPeer
        }

        func closeControl() {
            if control >= 0 {
                close(control)
                control = -1
            }
        }

        func markReaped() { reaped = true }

        func dispose() {
            closeControl()
            close(listenerPeer)
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
            try verifyHandshakeLockAndRevoke(executable: executable)
            try verifyLockThenImmediateRevoke(executable: executable)
            try verifyLockThenHostEOF(executable: executable)
            try verifyLockThreadCreationFailure(executable: executable)
            try verifyPartialFrameDeadline(executable: executable)
            try verifyUndrainedWriteBufferDeadline(executable: executable)
            try verifyProcessExitClosesLocalDescriptors(executable: executable)
            print("Gate helper socketpair lifecycle fixture passed")
            return 0
        } catch {
            fputs("Gate helper socketpair lifecycle fixture failed: \(error)\n", stderr)
            return 1
        }
    }

    private static func verifyHandshakeLockAndRevoke(executable: String) throws {
        let child = try spawnFixtureChild(executable: executable)
        defer { child.dispose() }
        let channel = try GateHelperChannel(descriptor: child.control)
        let session = try startSession(channel)
        let ready = session.ready
        try require(ready.snapshot == GateHelperSnapshot(bound: true, open: true,
                                                         generation: GateHelperChild.fixtureGeneration,
                                                         activePairs: 1, pending: 1),
                    "READY must atomically report the seeded active and pending slots")

        try channel.send(message(session, generation: GateHelperChild.fixtureGeneration,
                                 sequence: 2, kind: .status))
        let status = try receive(channel, "STATUS")
        try require(status.kind == .status && status.sequence == 2 &&
                    status.snapshot == ready.snapshot, "STATUS must return one consistent snapshot")

        var wrongNonce = session.nonce
        wrongNonce[0] ^= 0x01
        try channel.send(message(session, nonce: wrongNonce,
                                 generation: GateHelperChild.fixtureGeneration,
                                 sequence: 3, kind: .status))
        let nonceReject = try receive(channel, "wrong-nonce rejection")
        try require(nonceReject.kind == .rejected && nonceReject.reason == .nonce,
                    "wrong nonce must not consume the next valid sequence")

        try channel.send(message(session, generation: GateHelperChild.fixtureGeneration,
                                 sequence: 2, kind: .status))
        let sequenceReject = try receive(channel, "replayed-sequence rejection")
        try require(sequenceReject.kind == .rejected && sequenceReject.reason == .sequence,
                    "replayed sequence must be rejected")

        try channel.send(message(session, generation: GateHelperChild.fixtureGeneration - 1,
                                 sequence: 3, kind: .status))
        let generationReject = try receive(channel, "stale-generation rejection")
        try require(generationReject.kind == .rejected && generationReject.reason == .generation,
                    "stale generation must be rejected and consume its valid sequence")

        try channel.send(message(session, generation: GateHelperChild.fixtureGeneration,
                                 sequence: 4, kind: .status))
        let currentStatus = try receive(channel, "STATUS after rejects")
        try require(currentStatus.kind == .status && currentStatus.sequence == 4 &&
                    currentStatus.snapshot == ready.snapshot,
                    "rejected messages must not mutate Gate state")

        try channel.send(message(session, generation: GateHelperChild.fixtureGeneration,
                                 sequence: 5, kind: .lock))
        try expectRelayPeersClosed(child)
        try expectNoControlMessage(child.control, "LOCK must wait while pending slot is registered")
        try channel.send(message(session, generation: GateHelperChild.fixtureGeneration,
                                 sequence: 6, kind: .fixtureReleasePending))
        let lockReplies = try collectUntil(channel, wanted: [
            (.locked, 5), (.fixturePendingReleased, 6),
        ])
        let locked = lockReplies.first { $0.kind == .locked }
        try require(locked?.snapshot == GateHelperSnapshot(bound: true, open: false,
                                                           generation: GateHelperChild.fixtureGeneration,
                                                           activePairs: 0, pending: 0),
                    "LOCK reply must be an atomic bound/closed/empty readback")

        try channel.send(message(session, generation: GateHelperChild.fixtureGeneration,
                                 sequence: 7, kind: .revoke))
        let revoked = try receive(channel, "REVOKED")
        try require(revoked.kind == .revoked && revoked.snapshot == GateHelperSnapshot(
            bound: false, open: false, generation: GateHelperChild.fixtureGeneration,
            activePairs: 0, pending: 0), "REVOKE must close the listener and return a final snapshot")
        try expectEOF(child.listenerPeer, "listener peer after revoke")
        try waitForExit(child, expectedExitCode: 0)
    }

    private static func verifyLockThenImmediateRevoke(executable: String) throws {
        let child = try spawnFixtureChild(executable: executable)
        defer { child.dispose() }
        let channel = try GateHelperChannel(descriptor: child.control)
        let session = try startSession(channel)
        try require(session.ready.kind == .ready, "READY before immediate revoke sequence")

        try channel.send(message(session, generation: GateHelperChild.fixtureGeneration,
                                 sequence: 2, kind: .lock))
        try channel.send(message(session, generation: GateHelperChild.fixtureGeneration,
                                 sequence: 3, kind: .revoke))
        try expectRelayPeersClosed(child)
        try expectNoControlMessage(child.control, "REVOKE must wait for the active LOCK worker")
        try channel.send(message(session, generation: GateHelperChild.fixtureGeneration,
                                 sequence: 4, kind: .fixtureReleasePending))

        let replies = try collectUntil(channel, wanted: [
            (.locked, 2), (.revoked, 3), (.fixturePendingReleased, 4),
        ])
        let locked = replies.first { $0.kind == .locked }
        let revoked = replies.first { $0.kind == .revoked }
        try require(locked?.snapshot == GateHelperSnapshot(bound: true, open: false,
                                                           generation: GateHelperChild.fixtureGeneration,
                                                           activePairs: 0, pending: 0),
                    "LOCK completion must be collected before REVOKE destroys Gate")
        try require(revoked?.snapshot?.bound == false && revoked?.snapshot?.activePairs == 0,
                    "deferred REVOKE must observe the completed, empty Gate")
        try expectEOF(child.listenerPeer, "listener peer after deferred revoke")
        try waitForExit(child, expectedExitCode: 0)
    }

    private static func verifyLockThenHostEOF(executable: String) throws {
        let child = try spawnFixtureChild(executable: executable)
        defer { child.dispose() }
        let channel = try GateHelperChannel(descriptor: child.control)
        let session = try startSession(channel)
        try channel.send(message(session, generation: GateHelperChild.fixtureGeneration,
                                 sequence: 2, kind: .lock))
        try expectRelayPeersClosed(child)
        child.closeControl()
        try waitForExit(child, expectedExitCode: 0)
        try expectEOF(child.listenerPeer, "listener peer after host EOF")
        try expectEOF(child.activeClientPeer, "active client peer after host EOF")
        try expectEOF(child.activeUpstreamPeer, "active upstream peer after host EOF")
        try expectEOF(child.pendingClientPeer, "pending client peer after host EOF")
        try expectEOF(child.pendingUpstreamPeer, "pending upstream peer after host EOF")
    }

    private static func verifyLockThreadCreationFailure(executable: String) throws {
        let child = try spawnFixtureChild(executable: executable)
        defer { child.dispose() }
        let channel = try GateHelperChannel(descriptor: child.control)
        let session = try startSession(channel)
        try channel.send(message(session, generation: GateHelperChild.fixtureGeneration,
                                 sequence: 2, kind: .fixtureFailNextLockThread))
        let armed = try receive(channel, "thread-create failure injection acknowledgement")
        try require(armed.kind == .fixtureArmed && armed.sequence == 2,
                    "fixture must arm a single lock-worker creation failure")
        try channel.send(message(session, generation: GateHelperChild.fixtureGeneration,
                                 sequence: 3, kind: .lock))
        let failed = try receive(channel, "fail-closed thread-create response")
        try require(failed.kind == .rejected && failed.reason == .native &&
                    failed.snapshot == GateHelperSnapshot(bound: false, open: false,
                                                         generation: GateHelperChild.fixtureGeneration,
                                                         activePairs: 0, pending: 0),
                    "worker creation failure must revoke the listener and all relay slots")
        try expectEOF(child.listenerPeer, "listener peer after worker creation failure")
        try expectEOF(child.activeClientPeer, "active client peer after worker creation failure")
        try expectEOF(child.activeUpstreamPeer, "active upstream peer after worker creation failure")
        try expectEOF(child.pendingClientPeer, "pending client peer after worker creation failure")
        try expectEOF(child.pendingUpstreamPeer, "pending upstream peer after worker creation failure")
        try waitForExit(child, expectedExitCode: 0)
    }

    private static func verifyPartialFrameDeadline(executable: String) throws {
        let child = try spawnFixtureChild(executable: executable)
        defer { child.dispose() }
        let channel = try GateHelperChannel(descriptor: child.control)
        let session = try startSession(channel)
        let body = try JSONEncoder().encode(message(session, generation: GateHelperChild.fixtureGeneration,
                                                    sequence: 2, kind: .status))
        let length = UInt32(body.count)
        let partial = [UInt8(length >> 24), UInt8((length >> 16) & 0xff),
                       UInt8((length >> 8) & 0xff), UInt8(length & 0xff), body[0]]
        let written = partial.withUnsafeBytes { send(channel.descriptor, $0.baseAddress, $0.count, 0) }
        try require(written == partial.count, "send only a frame header and one body byte")
        try expectEOF(child.listenerPeer, "listener peer after partial-frame deadline")
        try expectEOF(child.activeClientPeer, "active client peer after partial-frame deadline")
        try expectEOF(child.pendingClientPeer, "pending client peer after partial-frame deadline")
        try waitForExit(child, expectedExitCode: 0)
    }

    private static func verifyUndrainedWriteBufferDeadline(executable: String) throws {
        let child = try spawnFixtureChild(executable: executable, controlSendBuffer: 512)
        defer { child.dispose() }
        let channel = try GateHelperChannel(descriptor: child.control)
        let session = try startSession(channel)
        try require(session.ready.kind == .ready, "READY before non-reading host test")

        var sent = 0
        for sequence in UInt64(2)...UInt64(129) {
            do {
                try channel.send(message(session, generation: GateHelperChild.fixtureGeneration,
                                         sequence: sequence, kind: .status))
                sent += 1
            } catch {
                break
            }
        }
        try require(sent == 128, "queue the request flood while the host leaves replies unread")
        // Keep the host endpoint open and deliberately never read responses.
        try expectEOF(child.listenerPeer, "listener peer after stalled reply writer")
        try expectEOF(child.activeClientPeer, "active client peer after stalled reply writer")
        try expectEOF(child.pendingClientPeer, "pending client peer after stalled reply writer")
        try waitForExit(child, expectedExitCode: 0)
    }

    private static func verifyProcessExitClosesLocalDescriptors(executable: String) throws {
        let child = try spawnFixtureChild(executable: executable)
        defer { child.dispose() }
        let channel = try GateHelperChannel(descriptor: child.control)
        let session = try startSession(channel)
        try require(session.ready.snapshot?.bound == true,
                    "crash fixture must own its Unix listener endpoint before termination")
        try require(kill(child.pid, SIGKILL) == 0, "terminate dedicated fixture child")
        try waitForSignal(child, expectedSignal: SIGKILL)
        try expectEOF(child.listenerPeer, "listener peer after helper exit")
        try expectEOF(child.activeClientPeer, "active client peer after helper exit")
        try expectEOF(child.activeUpstreamPeer, "active upstream peer after helper exit")
        try expectEOF(child.pendingClientPeer, "pending client peer after helper exit")
        try expectEOF(child.pendingUpstreamPeer, "pending upstream peer after helper exit")
    }

    private static func startSession(_ channel: GateHelperChannel) throws
        -> (nonce: [UInt8], epoch: UInt64, ready: GateHelperMessage) {
        let nonce = freshNonce()
        let epoch = freshEpoch()
        try channel.send(GateHelperMessage(version: 1, nonce: nonce, epoch: epoch,
                                           generation: 0, sequence: 1, kind: .hello))
        let ready = try receive(channel, "READY")
        try require(ready.kind == .ready && ready.sequence == 1 && ready.nonce == nonce &&
                    ready.epoch == epoch, "READY must bind the request nonce and epoch")
        return (nonce, epoch, ready)
    }

    private static func spawnFixtureChild(executable: String,
                                          controlSendBuffer: Int32? = nil) throws -> Child {
        let control = try socketPair()
        let listener = try socketPair()
        let activeClient = try socketPair()
        let activeUpstream = try socketPair()
        let pendingClient = try socketPair()
        let pendingUpstream = try socketPair()
        let sentinel = try socketPair()
        if let controlSendBuffer {
            var size = controlSendBuffer
            try require(setsockopt(control[1], SOL_SOCKET, SO_SNDBUF, &size,
                                   socklen_t(MemoryLayout<Int32>.size)) == 0,
                        "reduce helper reply socket buffer")
            var requestBuffer: Int32 = 262_144
            try require(setsockopt(control[1], SOL_SOCKET, SO_RCVBUF, &requestBuffer,
                                   socklen_t(MemoryLayout<Int32>.size)) == 0,
                        "increase helper request queue for the write-stall fixture")
            try require(setsockopt(control[0], SOL_SOCKET, SO_SNDBUF, &requestBuffer,
                                   socklen_t(MemoryLayout<Int32>.size)) == 0,
                        "allow the host fixture to queue requests without reading replies")
        }

        var parentDescriptors = [control[0], listener[0], activeClient[0], activeUpstream[0],
                                 pendingClient[0], pendingUpstream[0], sentinel[0], sentinel[1]]
        var sourceDescriptors: [Int32] = []
        do {
            let sentinelSource = try duplicateDescriptor(sentinel[0], minimum: 128)
            sourceDescriptors.append(sentinelSource)
            for descriptor in [control[1], listener[1], activeClient[1], activeUpstream[1],
                               pendingClient[1], pendingUpstream[1]] {
                sourceDescriptors.append(try duplicateDescriptor(descriptor, minimum: 256))
            }
            let childSourceEndpoints = [control[1], listener[1], activeClient[1], activeUpstream[1],
                                        pendingClient[1], pendingUpstream[1]]
            for descriptor in childSourceEndpoints { close(descriptor) }
            parentDescriptors.removeAll { childSourceEndpoints.contains($0) }

            var actions: posix_spawn_file_actions_t?
            try require(posix_spawn_file_actions_init(&actions) == 0, "initialize spawn file actions")
            defer { posix_spawn_file_actions_destroy(&actions) }
            let inherited = Array(zip(sourceDescriptors.dropFirst(), [3, 4, 5, 6, 7, 8]))
            for (source, target) in inherited {
                try require(posix_spawn_file_actions_adddup2(&actions, source, Int32(target)) == 0,
                            "add fixture FD whitelist entry")
                try require(posix_spawn_file_actions_addclose(&actions, source) == 0,
                            "close fixture source FD after dup")
            }

            var attributes: posix_spawnattr_t?
            try require(posix_spawnattr_init(&attributes) == 0, "initialize spawn attributes")
            defer { posix_spawnattr_destroy(&attributes) }
            try require(posix_spawnattr_setflags(&attributes,
                                                 Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)) == 0,
                        "enable close-on-exec default for helper")

            let arguments = [executable, "--helper-child", "3", "4", "5", "6", "7", "8",
                             String(sentinelSource)]
            let cArguments = arguments.map { strdup($0) }
            defer { cArguments.forEach { free($0) } }
            var argv = cArguments + [nil]
            var emptyEnvironment: [UnsafeMutablePointer<CChar>?] = [nil]
            var pid: pid_t = -1
            let spawnResult = executable.withCString { path in
                argv.withUnsafeMutableBufferPointer { argumentBuffer in
                    emptyEnvironment.withUnsafeMutableBufferPointer { environmentBuffer in
                        posix_spawn(&pid, path, &actions, &attributes,
                                    argumentBuffer.baseAddress!, environmentBuffer.baseAddress!)
                    }
                }
            }
            try require(spawnResult == 0 && pid > 0, "spawn dedicated Gate helper fixture: \(spawnResult)")

            for descriptor in sourceDescriptors { close(descriptor) }
            close(sentinelSource)
            close(sentinel[0]); close(sentinel[1])
            parentDescriptors.removeAll { $0 == sentinel[0] || $0 == sentinel[1] }
            return Child(pid: pid, control: control[0], listenerPeer: listener[0],
                         activeClientPeer: activeClient[0], activeUpstreamPeer: activeUpstream[0],
                         pendingClientPeer: pendingClient[0], pendingUpstreamPeer: pendingUpstream[0])
        } catch {
            for descriptor in parentDescriptors { close(descriptor) }
            for descriptor in sourceDescriptors { close(descriptor) }
            throw error
        }
    }

    private static func socketPair() throws -> [Int32] {
        var descriptors: [Int32] = [-1, -1]
        let result = descriptors.withUnsafeMutableBufferPointer {
            socketpair(AF_UNIX, SOCK_STREAM, 0, $0.baseAddress!)
        }
        try require(result == 0, "create anonymous socketpair: \(errno)")
        for descriptor in descriptors {
            var noSignal: Int32 = 1
            try require(setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE,
                                   &noSignal, socklen_t(MemoryLayout<Int32>.size)) == 0,
                        "disable SIGPIPE on fixture socket")
        }
        return descriptors
    }

    private static func duplicateDescriptor(_ descriptor: Int32, minimum: Int32) throws -> Int32 {
        let copy = fcntl(descriptor, F_DUPFD_CLOEXEC, minimum)
        try require(copy >= minimum, "move fixture FD above the spawn whitelist")
        return copy
    }

    private static func message(_ session: (nonce: [UInt8], epoch: UInt64, ready: GateHelperMessage),
                                nonce: [UInt8]? = nil,
                                generation: UInt64,
                                sequence: UInt64,
                                kind: GateHelperKind) -> GateHelperMessage {
        GateHelperMessage(version: 1, nonce: nonce ?? session.nonce, epoch: session.epoch,
                          generation: generation, sequence: sequence, kind: kind)
    }

    private static func freshNonce() -> [UInt8] {
        (0..<32).map { _ in UInt8.random(in: UInt8.min...UInt8.max) }
    }

    private static func freshEpoch() -> UInt64 {
        UInt64.random(in: 1...UInt64.max)
    }

    private static func receive(_ channel: GateHelperChannel, _ label: String) throws
        -> GateHelperMessage {
        do { return try channel.receive() }
        catch { throw FixtureFailure("read \(label): \(error)") }
    }

    private static func collectUntil(_ channel: GateHelperChannel,
                                     wanted: [(GateHelperKind, UInt64)]) throws -> [GateHelperMessage] {
        var pending = wanted
        var messages: [GateHelperMessage] = []
        while !pending.isEmpty {
            let response = try receive(channel, "expected lifecycle replies")
            guard let index = pending.firstIndex(where: {
                $0.0 == response.kind && $0.1 == response.sequence
            }) else { throw FixtureFailure("unexpected lifecycle reply \(response.kind)/\(response.sequence)") }
            pending.remove(at: index)
            messages.append(response)
        }
        return messages
    }

    private static func expectRelayPeersClosed(_ child: Child) throws {
        try expectEOF(child.activeClientPeer, "active client peer after lock")
        try expectEOF(child.activeUpstreamPeer, "active upstream peer after lock")
        try expectEOF(child.pendingClientPeer, "pending client peer after lock")
        try expectEOF(child.pendingUpstreamPeer, "pending upstream peer after lock")
    }

    private static func expectEOF(_ descriptor: Int32, _ label: String) throws {
        try require(waitReadable(descriptor, timeout: timeoutMillis), "wait for \(label)")
        var byte: UInt8 = 0
        let count = recv(descriptor, &byte, 1, 0)
        try require(count == 0, "expected EOF from \(label), got \(count)")
    }

    private static func expectNoControlMessage(_ descriptor: Int32, _ label: String) throws {
        var event = pollfd(fd: descriptor, events: Int16(POLLIN | POLLHUP), revents: 0)
        let result = poll(&event, 1, 250)
        try require(result == 0, "\(label); control channel became readable or closed")
    }

    private static func waitReadable(_ descriptor: Int32, timeout: Int32) -> Bool {
        var event = pollfd(fd: descriptor, events: Int16(POLLIN | POLLHUP), revents: 0)
        return poll(&event, 1, timeout) > 0 && (event.revents & Int16(POLLIN | POLLHUP)) != 0
    }

    private static func waitForExit(_ child: Child, expectedExitCode: Int32) throws {
        var status: Int32 = 0
        try require(waitpid(child.pid, &status, 0) == child.pid, "wait for graceful helper exit")
        child.markReaped()
        try require((status & 0x7f) == 0 && ((status >> 8) & 0xff) == expectedExitCode,
                    "helper exited with status \(status), expected \(expectedExitCode)")
    }

    private static func waitForSignal(_ child: Child, expectedSignal: Int32) throws {
        var status: Int32 = 0
        try require(waitpid(child.pid, &status, 0) == child.pid, "wait for terminated helper")
        child.markReaped()
        try require((status & 0x7f) != 0x7f && (status & 0x7f) == expectedSignal,
                    "helper status \(status) did not report signal \(expectedSignal)")
    }

    private static func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        if !condition() { throw FixtureFailure(message) }
    }
}

private struct FixtureFailure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}
