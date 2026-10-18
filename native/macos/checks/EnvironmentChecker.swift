import Foundation
import Darwin
import SystemConfiguration
import CryptoKit

// A diagnostic result is never an authorization or an enforcement readback.
// The authenticated native policy sink and launcher must make those decisions.
enum EnvironmentCheckFailure: Error, Equatable {
    case observation(String)
    case probe(String, retryable: Bool)
    case configuration(String)
    case networkChanged
    case exitMismatch
}

struct ListenerIdentity: Equatable {
    let pid: Int32
    let executable: String
    let birth: String
    let bindAddress: String
}

struct EnvironmentSnapshot: Equatable {
    let networkGeneration: UInt64
    let physicalNetwork: String
    let proxyDescription: String
    let tunRoute: String
    let tunInterface: String
    let extensionList: String
    let luluPreferences: Data
    let upstream: [ListenerIdentity]
    let legacyIngress: [ListenerIdentity]
    let rootPortObservation: RootPortObserver.Diagnostic?

    static func == (lhs: EnvironmentSnapshot, rhs: EnvironmentSnapshot) -> Bool {
        let observerFactsMatch: Bool
        switch (lhs.rootPortObservation, rhs.rootPortObservation) {
        case (nil, nil): observerFactsMatch = true
        case let (left?, right?): observerFactsMatch = left.sameFacts(as: right)
        default: observerFactsMatch = false
        }
        return lhs.networkGeneration == rhs.networkGeneration &&
            lhs.physicalNetwork == rhs.physicalNetwork &&
            lhs.proxyDescription == rhs.proxyDescription &&
            lhs.tunRoute == rhs.tunRoute && lhs.tunInterface == rhs.tunInterface &&
            lhs.extensionList == rhs.extensionList && lhs.luluPreferences == rhs.luluPreferences &&
            lhs.upstream == rhs.upstream && lhs.legacyIngress == rhs.legacyIngress && observerFactsMatch
    }
}

protocol EnvironmentSource {
    func snapshot() throws -> EnvironmentSnapshot
}

// One deadline covers local readbacks, both sites and the single admitted retry.
final class EnvironmentInspectionBudget {
    static let limitNS: UInt64 = 25_000_000_000
    let startedAtNS: UInt64
    let isCurrent: () -> Bool
    private let clock: () -> UInt64
    private(set) var probeDiagnostics: [String] = []

    init(clock: @escaping () -> UInt64 = NativeEnvironmentChecker.continuousNowNS,
         isCurrent: @escaping () -> Bool = { true }) {
        self.clock = clock
        self.isCurrent = isCurrent
        startedAtNS = clock()
    }

    func remainingSeconds() throws -> Double {
        guard isCurrent() else { throw EnvironmentCheckFailure.observation("inspection_cancelled") }
        let now = clock()
        guard startedAtNS > 0, now >= startedAtNS else {
            throw EnvironmentCheckFailure.observation("inspection_clock")
        }
        let elapsed = now - startedAtNS
        guard elapsed < Self.limitNS else {
            throw EnvironmentCheckFailure.observation("inspection_budget_exceeded_elapsed_ms_\(min(elapsed / 1_000_000, 999_999))")
        }
        return Double(Self.limitNS - elapsed) / 1_000_000_000
    }

    func record(_ key: String) {
        // Fixed site/cause labels only; never response bodies, addresses or stderr.
        if probeDiagnostics.count < 4 { probeDiagnostics.append(String(key.prefix(128))) }
    }

    func diagnostic(_ failure: EnvironmentCheckFailure?) -> String {
        let key: String
        switch failure {
        case .observation(let value), .probe(let value, _): key = "observation_\(value)"
        case .configuration(let value): key = "configuration_\(value)"
        case .networkChanged: key = "network_changed"
        case .exitMismatch: key = "fixed_ip_mismatch"
        case nil: key = "environment_check"
        }
        return ([key] + probeDiagnostics.filter { "observation_" + $0 != key }).joined(separator: "\n")
    }
}

protocol HTTPSExitProbe {
    // Offline fixtures inject capture results; production uses fixed HTTPS URLs.
    func observedAddresses(proxyPort: UInt16, budget: EnvironmentInspectionBudget) throws -> [String]
}

struct EnvironmentCheckReport {
    let observationsMatch: Bool
    let observedIP: String?
    let failure: EnvironmentCheckFailure?
    let beforeGeneration: UInt64?
    let afterGeneration: UInt64?
    let networkFingerprint: String?
    let upstreamFingerprint: String?
    let ingressFingerprint: String?
    let rootPortObservation: RootPortObserver.Diagnostic?
    let startedAtContinuousNS: UInt64
    let checkedAtContinuousNS: UInt64
    let productionObserved: Bool
    let probeDiagnostics: [String]
    let diagnosticOnly = true

    // Deliberately no `passed`, `enforcementVerified`, or permit field.
    fileprivate init(_ match: Bool, _ ip: String?, _ failure: EnvironmentCheckFailure?,
                     _ before: UInt64?, _ after: UInt64?, _ fingerprint: String?,
                     _ upstreamFingerprint: String?, _ ingressFingerprint: String?,
                     _ started: UInt64,
                     _ production: Bool,
                     _ rootPortObservation: RootPortObserver.Diagnostic? = nil,
                     _ probeDiagnostics: [String] = []) {
        observationsMatch = match
        observedIP = ip
        self.failure = failure
        beforeGeneration = before
        afterGeneration = after
        networkFingerprint = fingerprint
        self.upstreamFingerprint = upstreamFingerprint
        self.ingressFingerprint = ingressFingerprint
        self.rootPortObservation = rootPortObservation
        self.probeDiagnostics = probeDiagnostics
        startedAtContinuousNS = started
        checkedAtContinuousNS = NativeEnvironmentChecker.continuousNowNS()
        productionObserved = production
    }
}

struct NativeEnvironmentChecker {
    enum ProbePath { case upstream, entry, sunbrowserEntry }
    static let expectedIP = "65.195.109.98"
    static let upstreamPort: UInt16 = 7896
    static let legacyIngressPort: UInt16 = 17897
    static let sunbrowserIngressPort: UInt16 = 17898
    static let coreExecutable = "/Applications/FlClash.app/Contents/MacOS/FlClashCore"
    static let tunGateway = "198.18.0.1"

    private let source: EnvironmentSource
    private let probe: HTTPSExitProbe
    private let expectedIngressExecutable: String
    private let expectedIngressPID: Int32?
    private let productionObservation: Bool

    init(source: EnvironmentSource, probe: HTTPSExitProbe,
         expectedIngressExecutable: String) {
        self.source = source
        self.probe = probe
        self.expectedIngressExecutable = expectedIngressExecutable
        expectedIngressPID = nil
        productionObservation = false
    }

    private init(source: EnvironmentSource, probe: HTTPSExitProbe,
                 expectedIngressExecutable: String, expectedIngressPID: Int32,
                 productionObservation: Bool) {
        self.source = source
        self.probe = probe
        self.expectedIngressExecutable = expectedIngressExecutable
        self.expectedIngressPID = expectedIngressPID
        self.productionObservation = productionObservation
    }

    static func production(expectedIngressExecutable: String,
                           expectedIngressPID: Int32,
                           onNetworkChange: @escaping (String) -> Void) throws -> NativeEnvironmentChecker {
        guard expectedIngressPID > 0, expectedIngressExecutable.hasPrefix("/"),
              !expectedIngressExecutable.contains(".."),
              !expectedIngressExecutable.contains("//") else {
            throw EnvironmentCheckFailure.configuration("trusted_ingress_path")
        }
        return NativeEnvironmentChecker(source: try ProductionEnvironmentSource(
                onNetworkChange: onNetworkChange),
            probe: ProductionHTTPSExitProbe(), expectedIngressExecutable: expectedIngressExecutable,
            expectedIngressPID: expectedIngressPID,
            productionObservation: true)
    }

    // `inspect` retains gate state and never creates or renews a policy lease.
    // Production callers must construct the production source/probe locally;
    // an IPC result or caller-provided report cannot be elevated to authority.
    func inspect(path: ProbePath = .upstream,
                 validateRetry: (() throws -> Void)? = nil,
                 budget: EnvironmentInspectionBudget = EnvironmentInspectionBudget()) -> EnvironmentCheckReport {
        let started = budget.startedAtNS
        var before: EnvironmentSnapshot?
        var after: EnvironmentSnapshot?
        do {
            _ = try budget.remainingSeconds()
            let first = try source.snapshot()
            _ = try budget.remainingSeconds()
            before = first
            try validate(first, requiresIngress: path != .upstream)
            let port = path == .upstream ? Self.upstreamPort
                : path == .sunbrowserEntry ? Self.sunbrowserIngressPort : Self.legacyIngressPort
            var retried = false
            let addresses: [String]
            do { addresses = try probe.observedAddresses(proxyPort: port, budget: budget) }
            catch let error as EnvironmentCheckFailure {
                guard case .probe(_, retryable: true) = error, let validateRetry else { throw error }
                _ = try budget.remainingSeconds()
                try validateRetry()
                _ = try budget.remainingSeconds()
                retried = true
                addresses = try probe.observedAddresses(proxyPort: port, budget: budget)
            }
            _ = try budget.remainingSeconds()
            guard addresses.count == 2,
                  addresses.allSatisfy({ $0 == Self.expectedIP }) else {
                throw EnvironmentCheckFailure.exitMismatch
            }
            let second = try source.snapshot()
            after = second
            _ = try budget.remainingSeconds()
            try validate(second, requiresIngress: path != .upstream)
            guard first.networkGeneration == second.networkGeneration,
                  first == second else { throw EnvironmentCheckFailure.networkChanged }
            if retried, let validateRetry { try validateRetry() }
            _ = try budget.remainingSeconds()
            return EnvironmentCheckReport(true, Self.expectedIP, nil,
                                          first.networkGeneration, second.networkGeneration,
                                          Self.fingerprint(first),
                                          Self.listenerFingerprint(first.upstream),
                                          Self.listenerFingerprint(first.legacyIngress),
                                          started, productionObservation,
                                          first.rootPortObservation, budget.probeDiagnostics)
        } catch let error as EnvironmentCheckFailure {
            return EnvironmentCheckReport(false, nil, error,
                                          before?.networkGeneration, after?.networkGeneration, nil,
                                          nil, nil,
                                          started, productionObservation,
                                          after?.rootPortObservation ?? before?.rootPortObservation, budget.probeDiagnostics)
        } catch {
            return EnvironmentCheckReport(false, nil, .observation("unavailable"),
                                          before?.networkGeneration, after?.networkGeneration, nil,
                                          nil, nil,
                                          started, productionObservation,
                                          after?.rootPortObservation ?? before?.rootPortObservation, budget.probeDiagnostics)
        }
    }

    // Must only be called after authenticated native code has opened the gate
    // while all business workloads remain suspended. Never opens the gate.
    func probeThroughIngress(path: ProbePath = .entry, validateRetry: (() throws -> Void)? = nil,
                             budget: EnvironmentInspectionBudget = EnvironmentInspectionBudget()) -> EnvironmentCheckReport {
        inspect(path: path, validateRetry: validateRetry, budget: budget)
    }

    // Cheap local readback for a heartbeat. It deliberately makes no public
    // request and cannot reuse an earlier public-IP observation.
    func localSnapshot() throws -> (generation: UInt64, fingerprint: String) {
        let value = try source.snapshot()
        try validate(value, requiresIngress: false)
        return (value.networkGeneration, Self.fingerprint(value))
    }

    func renewalSnapshot() throws -> EnvironmentRenewalSnapshot {
        guard let source = source as? ProductionEnvironmentSource else {
            throw EnvironmentCheckFailure.observation("renewal_source_unavailable")
        }
        return try source.renewalSnapshot()
    }

    func checkExtensionHealth() throws {
        guard let source = source as? ProductionEnvironmentSource else {
            throw EnvironmentCheckFailure.observation("extension_source_unavailable")
        }
        try source.checkExtensionHealth()
    }

    static func listenerFingerprint(_ values: [ListenerIdentity]) -> String {
        let value = values.sorted { $0.pid < $1.pid }.map {
            "\($0.pid)\n\($0.executable)\n\($0.birth)\n\($0.bindAddress)"
        }.joined(separator: "\n")
        return SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    private static func fingerprint(_ value: EnvironmentSnapshot) -> String {
        let bytes = Data((value.physicalNetwork + "\n" + value.proxyDescription + "\n" +
            value.tunRoute + "\n" + value.tunInterface + "\n" + value.extensionList + "\n" +
            String(describing: value.upstream) + "\n" + String(describing: value.legacyIngress)).utf8)
        var hasher = SHA256()
        hasher.update(data: bytes)
        // Validation already requires every security-relevant LuLu switch to
        // be off and no active profile. Unrelated preference bytes may change
        // when the user edits another application's rules; they do not alter
        // this scope's network identity. The raw bytes still participate in
        // the before/after equality check within a single inspection.
        hasher.update(data: Data("lulu:disabled=off;allowDNS=off;allowLocalHost=off;useAllowList=off;currentProfile=none".utf8))
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    static func continuousNowNS() -> UInt64 {
        var info = mach_timebase_info_data_t()
        guard mach_timebase_info(&info) == KERN_SUCCESS, info.denom != 0 else { return 0 }
        let ticks = mach_continuous_time()
        return (ticks / UInt64(info.denom)) * UInt64(info.numer) +
            ((ticks % UInt64(info.denom)) * UInt64(info.numer)) / UInt64(info.denom)
    }

    private func validate(_ value: EnvironmentSnapshot, requiresIngress: Bool) throws {
        if let observation = value.rootPortObservation,
           let failure = RootPortObserver.admissionFailure(observation) {
            throw EnvironmentCheckFailure.observation(failure)
        }
        guard !value.physicalNetwork.isEmpty else { throw EnvironmentCheckFailure.observation("physical_network") }
        guard Self.proxyOff(value.proxyDescription) else { throw EnvironmentCheckFailure.configuration("system_proxy") }
        guard Self.tunValid(route: value.tunRoute, interface: value.tunInterface) else {
            throw EnvironmentCheckFailure.configuration("tun_route")
        }
        guard LuLuExtensionStatus.isEnabled(in: value.extensionList) else {
            throw EnvironmentCheckFailure.configuration("lulu_extension")
        }
        guard let prefs = try? PropertyListSerialization.propertyList(from: value.luluPreferences,
            options: [], format: nil) as? [String: Any],
            ["disabled", "allowDNS", "allowLocalHost", "useAllowList"].allSatisfy({
                (prefs[$0] as? NSNumber)?.boolValue != true
            }), (prefs["currentProfile"] == nil || prefs["currentProfile"] as? String == "") else {
            throw EnvironmentCheckFailure.configuration("lulu_preferences")
        }
        guard value.upstream.count == 1,
              value.upstream[0].executable == Self.coreExecutable,
              value.upstream[0].bindAddress == "127.0.0.1:\(Self.upstreamPort)",
              value.upstream[0].pid > 0, !value.upstream[0].birth.isEmpty else {
            throw EnvironmentCheckFailure.configuration("upstream_identity")
        }
        guard (!requiresIngress || value.legacyIngress.count == 1),
              value.legacyIngress.count <= 1,
              value.legacyIngress.allSatisfy({ entry in
                  entry.pid > 0 && (expectedIngressPID.map { $0 == entry.pid } ?? true) &&
                  entry.executable == expectedIngressExecutable && !entry.birth.isEmpty &&
                  entry.bindAddress == "127.0.0.1:\(Self.legacyIngressPort)" }) else {
            throw EnvironmentCheckFailure.configuration("legacy_ingress_identity")
        }
    }

    static func proxyOff(_ output: String) -> Bool {
        guard output.range(of: #"^\s*<dictionary>\s*\{"#, options: .regularExpression) != nil else { return false }
        let switches = Set(["HTTPEnable", "HTTPSEnable", "SOCKSEnable",
                            "ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable"])
        for key in ["HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable"] {
            let lines = output.split(separator: "\n").compactMap { line -> String? in
                let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                return parts.count == 2 && parts[0] == key ? parts[1] : nil
            }
            guard lines.count <= 1, lines.allSatisfy({ $0 == "0" }) else { return false }
        }
        // Reject a malformed switch that happens to use an unexpected value.
        for line in output.split(separator: "\n") {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            if parts.count == 2 && switches.contains(parts[0]) && !["0", "1"].contains(parts[1]) { return false }
        }
        return true
    }

    static func tunValid(route: String, interface: String) -> Bool {
        let fields = Dictionary(route.split(separator: "\n").compactMap { line -> (String, String)? in
            guard let colon = line.firstIndex(of: ":") else { return nil }
            return (String(line[..<colon]).trimmingCharacters(in: .whitespaces),
                    String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces))
        }, uniquingKeysWith: { first, _ in first })
        guard let name = fields["interface"],
              name.range(of: #"^utun[0-9]+$"#, options: .regularExpression) != nil,
              fields["gateway"] == tunGateway else { return false }
        return interface.split(separator: "\n").contains { line in
            let words = line.split(whereSeparator: { $0.isWhitespace }).map(String.init)
            return words.count >= 2 && words[0] == "inet" && words[1] == tunGateway
        }
    }
}

private final class WeakNetworkCounter {
    weak var value: NetworkChangeCounter?
    init(_ value: NetworkChangeCounter) { self.value = value }
}

private final class NetworkChangeCounter {
    private let lock = NSLock()
    private var generation: UInt64 = 0
    private let onNetworkChange: (String) -> Void
    private let queue = DispatchQueue(label: "guard.environment.network-changes")
    private var store: SCDynamicStore?
    private var wifiObserver: WiFiAssociationEventMonitor?
    private var trackedScope = NetworkEventScope()
    private var notificationMonitoringAvailable = true

    init(onNetworkChange: @escaping (String) -> Void) throws {
        self.onNetworkChange = onNetworkChange
        let box = WeakNetworkCounter(self)
        var context = SCDynamicStoreContext(version: 0, info: Unmanaged.passUnretained(box).toOpaque(),
            retain: { info in
                return UnsafeRawPointer(Unmanaged<WeakNetworkCounter>.fromOpaque(info).retain().toOpaque())
            }, release: { info in
                Unmanaged<WeakNetworkCounter>.fromOpaque(info).release()
            }, copyDescription: nil)
        guard let created = SCDynamicStoreCreate(nil, "ClaudeGuardEnvironment" as CFString,
            { store, keys, info in
                guard let info else { return }
                guard let counter = Unmanaged<WeakNetworkCounter>.fromOpaque(info).takeUnretainedValue().value else { return }
                counter.dynamicStoreChanged(store, keys: keys as? [String])
            }, &context),
            Self.activeScope(from: created).isUsable,
            Self.installNotificationKeys(on: created, scope: Self.activeScope(from: created)),
            SCDynamicStoreSetDispatchQueue(created, queue) else {
            throw EnvironmentCheckFailure.observation("network_monitor")
        }
        store = created
        trackedScope = Self.activeScope(from: created)

        do {
            wifiObserver = try WiFiAssociationEventMonitor { [weak box] event in
                guard let counter = box?.value else { return }
                counter.queue.async { [weak counter] in
                    counter?.record(event.category)
                }
            }
        } catch {
            SCDynamicStoreSetDispatchQueue(created, nil)
            store = nil
            throw EnvironmentCheckFailure.observation("wifi_event_monitor")
        }
    }

    deinit { if let store { SCDynamicStoreSetDispatchQueue(store, nil) } }

    private static func activeScope(from store: SCDynamicStore) -> NetworkEventScope {
        var scope = NetworkEventScope()
        for family in ["IPv4", "IPv6"] {
            guard let value = SCDynamicStoreCopyValue(store,
                    "State:/Network/Global/\(family)" as CFString) as? [String: Any] else { continue }
            if let service = value["PrimaryService"] as? String,
               NetworkEventPolicy.validPathComponent(service) {
                scope.services.insert(service)
            }
            if let interface = value["PrimaryInterface"] as? String,
               NetworkEventPolicy.validPathComponent(interface) {
                scope.interfaces.insert(interface)
            }
        }
        return scope
    }

    private static func installNotificationKeys(on store: SCDynamicStore,
                                                scope: NetworkEventScope) -> Bool {
        SCDynamicStoreSetNotificationKeys(store,
            NetworkEventPolicy.subscriptionKeys(scope: scope) as CFArray, nil)
    }

    private func record(_ category: NetworkEventCategory) {
        lock.lock()
        generation &+= 1
        lock.unlock()
        onNetworkChange("network_\(category.rawValue)")
    }

    private func dynamicStoreChanged(_ store: SCDynamicStore, keys: [String]?) {
        let currentScope = Self.activeScope(from: store)
        let effectiveScope = trackedScope.union(currentScope)
        var categories = NetworkEventPolicy.classify(keys, scope: effectiveScope)
        let scopeChanged = currentScope != trackedScope
        trackedScope = currentScope

        if scopeChanged && !Self.installNotificationKeys(on: store, scope: currentScope) {
            categories.insert(.notificationUnavailable)
            lock.lock()
            notificationMonitoringAvailable = false
            lock.unlock()
        }
        if let category = categories.min(by: { $0.rawValue < $1.rawValue }) { record(category) }
    }

    func value() -> UInt64 {
        queue.sync {}
        lock.lock(); defer { lock.unlock() }
        if !notificationMonitoringAvailable || wifiObserver?.isLive != true {
            generation &+= 1
        }
        return generation
    }
}

// Fixed read-only OS observations. No caller-selected command, path, port, URL
// or environment enters this production adapter.
final class ProductionEnvironmentSource: EnvironmentSource {
    private let changes: NetworkChangeCounter
    init(onNetworkChange: @escaping (String) -> Void) throws {
        changes = try NetworkChangeCounter(onNetworkChange: onNetworkChange)
    }

    func snapshot() throws -> EnvironmentSnapshot {
        let start = changes.value()
        let physical = try Self.run("/usr/sbin/scutil", ["--nwi"])
            + "\n" + Self.run("/sbin/ifconfig", ["-a"])
        let proxy = try Self.run("/usr/sbin/scutil", ["--proxy"])
        let route = try Self.run("/sbin/route", ["-n", "get", "1.1.1.1"])
        let names = route.split(separator: "\n").compactMap { line -> String? in
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            return parts.count == 2 && parts[0] == "interface" ? parts[1] : nil
        }
        guard names.count == 1, names[0].range(of: #"^utun[0-9]+$"#, options: .regularExpression) != nil else {
            throw EnvironmentCheckFailure.observation("tun_interface")
        }
        let tun = try Self.run("/sbin/ifconfig", [names[0]])
        let extensions = try Self.run("/usr/bin/systemextensionsctl", ["list"])
        let preferences = try Data(contentsOf: URL(fileURLWithPath:
            "/Library/Objective-See/LuLu/preferences.plist"), options: .mappedIfSafe)
        guard preferences.count <= 65_536 else { throw EnvironmentCheckFailure.observation("lulu_preferences_size") }
        let observed = RootPortObserver.readDiagnostic()
        let finish = changes.value()
        guard start == finish else { throw EnvironmentCheckFailure.networkChanged }
        return EnvironmentSnapshot(networkGeneration: finish, physicalNetwork: physical,
            proxyDescription: proxy, tunRoute: route, tunInterface: tun,
            extensionList: extensions, luluPreferences: preferences,
            upstream: observed.reportedUpstreamIdentities,
            legacyIngress: observed.reportedIngressIdentities,
            rootPortObservation: observed)
    }

    // Minimal renewal read: no shell commands, public probes, or LuLu plist
    // hashing. SCDynamicStore/Wi-Fi events and baseline vnode watches provide
    // immediate invalidation; the root observer pins both loopback owners.
    func renewalSnapshot() throws -> EnvironmentRenewalSnapshot {
        let before = changes.value()
        let observed = try RootPortObserver.read()
        let after = changes.value()
        guard before == after else { throw EnvironmentCheckFailure.networkChanged }
        return EnvironmentRenewalSnapshot(
            networkGeneration: after,
            upstreamFingerprint: NativeEnvironmentChecker.listenerFingerprint(observed.upstream),
            ingressFingerprint: NativeEnvironmentChecker.listenerFingerprint(observed.ingress))
    }

    func checkExtensionHealth() throws {
        let listing = try Self.run("/usr/bin/systemextensionsctl", ["list"], timeoutSeconds: 1)
        guard LuLuExtensionStatus.isEnabled(in: listing) else {
            throw EnvironmentCheckFailure.configuration("lulu_extension")
        }
    }

    // Diagnostic labels come from this fixed table, never command arguments,
    // stderr, arbitrary path components, or the inherited environment.
    static func commandFailureKey(path: String, terminationStatus: Int32?, timedOut: Bool) -> String {
        let labels = ["/usr/sbin/scutil": "scutil", "/sbin/ifconfig": "ifconfig",
                      "/sbin/route": "route", "/usr/bin/systemextensionsctl": "systemextensionsctl",
                      "/usr/bin/curl": "curl"]
        let label = labels[path] ?? "unknown"
        let status = terminationStatus.map(String.init) ?? "unavailable"
        return "command_failed_\(label)_status_\(status)_timeout_\(timedOut ? 1 : 0)"
    }

    struct ProcessCapture {
        let output: Data
        let terminationStatus: Int32?
        let timedOut: Bool
        let outputLimitExceeded: Bool
        let readFailed: Bool
        var cancelled = false
        let elapsedMS: UInt64
    }

    static func capture(_ path: String, _ arguments: [String],
                        timeoutSeconds: Double = 2,
                        isCurrent: (() -> Bool)? = nil) -> ProcessCapture {
        let started = DispatchTime.now().uptimeNanoseconds
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
        let out = Pipe()
        process.standardOutput = out; process.standardError = FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            return ProcessCapture(output: Data(), terminationStatus: nil, timedOut: false,
                                  outputLimitExceeded: false, readFailed: false,
                                  elapsedMS: (DispatchTime.now().uptimeNanoseconds - started) / 1_000_000)
        }
        let ownershipLock = NSLock()
        var finished = false
        var timedOut = false
        var cancelled = false
        let cancellation = DispatchSource.makeTimerSource(queue: .global())
        cancellation.setEventHandler {
            ownershipLock.lock(); defer { ownershipLock.unlock() }
            // finished fences the borrowed callback context before returning to Rust.
            if !finished, let isCurrent, !isCurrent(), process.isRunning {
                cancelled = true
                _ = Darwin.kill(process.processIdentifier, SIGKILL)
            }
        }
        if isCurrent != nil {
            cancellation.schedule(deadline: .now(), repeating: .milliseconds(50))
        }
        cancellation.resume()
        let timeout = DispatchWorkItem {
            ownershipLock.lock(); defer { ownershipLock.unlock() }
            if !finished && process.isRunning {
                timedOut = true
                _ = Darwin.kill(process.processIdentifier, SIGKILL)
            }
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeoutSeconds, execute: timeout)
        var data = Data()
        var outputLimitExceeded = false
        var readFailed = false
        var bytes = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = Darwin.read(out.fileHandleForReading.fileDescriptor, &bytes, bytes.count)
            if count < 0 {
                readFailed = true
                ownershipLock.lock()
                if !finished && process.isRunning { _ = Darwin.kill(process.processIdentifier, SIGKILL) }
                ownershipLock.unlock()
                break
            }
            if count == 0 { break }
            data.append(contentsOf: bytes[0..<count])
            if data.count > 65_536 {
                outputLimitExceeded = true
                ownershipLock.lock()
                if !finished && process.isRunning { _ = Darwin.kill(process.processIdentifier, SIGKILL) }
                ownershipLock.unlock()
                break
            }
        }
        process.waitUntilExit()
        ownershipLock.lock()
        finished = true
        let didTimeOut = timedOut
        let wasCancelled = cancelled
        ownershipLock.unlock()
        timeout.cancel()
        cancellation.cancel()
        return ProcessCapture(output: data, terminationStatus: process.terminationStatus,
                              timedOut: didTimeOut, outputLimitExceeded: outputLimitExceeded,
                              readFailed: readFailed, cancelled: wasCancelled,
                              elapsedMS: (DispatchTime.now().uptimeNanoseconds - started) / 1_000_000)
    }

    fileprivate static func run(_ path: String, _ arguments: [String], timeoutSeconds: Double = 2) throws -> String {
        let result = capture(path, arguments, timeoutSeconds: timeoutSeconds)
        guard result.terminationStatus == 0, !result.timedOut,
              !result.outputLimitExceeded, !result.readFailed,
              let text = String(data: result.output, encoding: .utf8) else {
            throw EnvironmentCheckFailure.observation(commandFailureKey(path: path,
                terminationStatus: result.terminationStatus, timedOut: result.timedOut))
        }
        return text
    }
}

final class ProductionHTTPSExitProbe: HTTPSExitProbe {
    struct CurlMetrics: Equatable {
        let connectSeconds: Double
        let connectResponse: Int
        let tlsSeconds: Double
        let firstByteSeconds: Double
        let responseStatus: Int
    }

    struct ParsedOutput {
        let body: String
        let metrics: CurlMetrics?
        let hasMetadataMarker: Bool
    }

    enum FailurePhase: String {
        case proxyTCP = "proxy_tcp"
        case proxyConnect = "proxy_connect"
        case tls = "tls"
        case response = "response"
        case process = "process"
        case unknown = "unknown"
    }

    enum Endpoint: String {
        case ipinfo
        case cloudflare
    }

    typealias Capture = ([String], Double, @escaping () -> Bool) -> ProductionEnvironmentSource.ProcessCapture
    private let capture: Capture
    init(capture: @escaping Capture = { arguments, timeout, isCurrent in
        ProductionEnvironmentSource.capture("/usr/bin/curl", arguments,
            timeoutSeconds: timeout, isCurrent: isCurrent)
    }) { self.capture = capture }

    private static let metadataMarker = "\n__CG_PROBE_METADATA_V1__:"
    // These fields contain only bounded timings and HTTP status numbers. The
    // response body and curl stderr are never copied into a diagnostic.
    private static let writeOutFormat = metadataMarker +
        "%{time_connect};%{http_connect};%{time_appconnect};%{time_starttransfer};%{http_code}\n"
    private static let curlDeadlineSeconds: Double = 8
    // Any reaping grace is also capped by the shared inspection deadline.
    private static let curlProcessDeadlineSeconds: Double = 10

    static func parseOutput(_ output: String) -> ParsedOutput {
        guard let marker = output.range(of: metadataMarker, options: .backwards) else {
            return ParsedOutput(body: output, metrics: nil, hasMetadataMarker: false)
        }
        let body = String(output[..<marker.lowerBound])
        let fields = output[marker.upperBound...].prefix { $0 != "\n" }
            .split(separator: ";", omittingEmptySubsequences: false)
        guard fields.count == 5,
              let connect = Double(fields[0]), connect.isFinite, connect >= 0,
              let connectResponse = Int(fields[1]),
              let tls = Double(fields[2]), tls.isFinite, tls >= 0,
              let firstByte = Double(fields[3]), firstByte.isFinite, firstByte >= 0,
              let responseStatus = Int(fields[4]),
              (0...999).contains(connectResponse), (0...999).contains(responseStatus) else {
            return ParsedOutput(body: body, metrics: nil, hasMetadataMarker: true)
        }
        return ParsedOutput(body: body,
            metrics: CurlMetrics(connectSeconds: connect, connectResponse: connectResponse,
                                 tlsSeconds: tls, firstByteSeconds: firstByte,
                                 responseStatus: responseStatus),
            hasMetadataMarker: true)
    }

    static func failurePhase(terminationStatus: Int32?, timedOut: Bool,
                             metrics: CurlMetrics?) -> FailurePhase {
        guard !timedOut, terminationStatus != nil else { return .process }
        guard let metrics else { return .unknown }
        if metrics.connectResponse != 0 && metrics.connectResponse != 200 { return .proxyConnect }
        if metrics.connectSeconds == 0 { return .proxyTCP }
        if metrics.connectResponse == 0 { return .proxyConnect }
        if metrics.tlsSeconds == 0 { return .tls }
        return .response
    }

    static func diagnosticKey(endpoint: Endpoint, terminationStatus: Int32?,
                              timedOut: Bool, phase: FailurePhase, elapsedMS: UInt64) -> String {
        let status = terminationStatus.map(String.init) ?? "unavailable"
        let cause: String
        if timedOut { cause = "process_timeout" }
        else {
            switch terminationStatus {
            case 7: cause = "connection_error"
            case 28: cause = "curl_timeout"
            case 35: cause = "tls_error"
            case 60: cause = "certificate_error"
            case 22: cause = "http_error"
            default: cause = "probe_error"
            }
        }
        return "https_probe_\(endpoint.rawValue)_status_\(status)_cause_\(cause)_phase_\(phase.rawValue)_elapsed_ms_\(elapsedMS)"
    }

    static func permitsRetry(terminationStatus: Int32?, timedOut: Bool, phase: FailurePhase) -> Bool {
        !timedOut && phase != .process && (terminationStatus == 7 || terminationStatus == 28)
    }

    private static func failure(endpoint: Endpoint, result: ProductionEnvironmentSource.ProcessCapture,
                                metrics: CurlMetrics?) -> EnvironmentCheckFailure {
        let phase = failurePhase(terminationStatus: result.terminationStatus,
                                 timedOut: result.timedOut || result.outputLimitExceeded || result.readFailed,
                                 metrics: metrics)
        let key = diagnosticKey(endpoint: endpoint, terminationStatus: result.terminationStatus,
                                timedOut: result.timedOut, phase: phase, elapsedMS: min(result.elapsedMS, 999_999))
        return .probe(key, retryable: permitsRetry(terminationStatus: result.terminationStatus,
                                                  timedOut: result.timedOut, phase: phase))
    }

    func observedAddresses(proxyPort: UInt16, budget: EnvironmentInspectionBudget) throws -> [String] {
        guard proxyPort == NativeEnvironmentChecker.upstreamPort ||
              proxyPort == NativeEnvironmentChecker.legacyIngressPort ||
              proxyPort == NativeEnvironmentChecker.sunbrowserIngressPort else {
            throw EnvironmentCheckFailure.configuration("proxy_port")
        }
        let proxy = "http://127.0.0.1:\(proxyPort)"
        let requests: [(Endpoint, String)] = [
            (.ipinfo, "https://ipinfo.io/ip"),
            (.cloudflare, "https://www.cloudflare.com/cdn-cgi/trace")
        ]
        return try requests.map { endpoint, url in
            let remaining = try budget.remainingSeconds()
            let result = capture(["--disable", "--silent", "--show-error",
                "--fail", "--connect-timeout", String(min(5, remaining)),
                "--max-time", String(min(Self.curlDeadlineSeconds, remaining)),
                "--proxy", proxy, "--noproxy", "", "--proto", "=https",
                "--write-out", Self.writeOutFormat, url],
                min(Self.curlProcessDeadlineSeconds, remaining), {
                    // Continuous time also detects a deadline crossed during machine sleep.
                    (try? budget.remainingSeconds()) != nil
                })
            if result.cancelled {
                budget.record("https_probe_\(endpoint.rawValue)_status_unavailable_cause_interrupted_phase_process_elapsed_ms_\(min(result.elapsedMS, 999_999))")
                _ = try budget.remainingSeconds()
                throw EnvironmentCheckFailure.observation("inspection_cancelled")
            }
            let parsed = Self.parseOutput(String(data: result.output, encoding: .utf8) ?? "")
            guard result.terminationStatus == 0, !result.timedOut,
                  !result.outputLimitExceeded, !result.readFailed,
                  parsed.hasMetadataMarker, parsed.metrics != nil else {
                let error = Self.failure(endpoint: endpoint, result: result, metrics: parsed.metrics)
                if case .probe(let key, _) = error { budget.record(key) }
                _ = try budget.remainingSeconds()
                throw error
            }
            let address: String
            switch endpoint {
            case .ipinfo: address = parsed.body.trimmingCharacters(in: .whitespacesAndNewlines)
            case .cloudflare:
                let rows = parsed.body.split(separator: "\n").filter { $0.hasPrefix("ip=") }
                address = rows.count == 1 ? String(rows[0].dropFirst(3)) : ""
            }
            let cause = address == NativeEnvironmentChecker.expectedIP ? "ok" : "exit_mismatch"
            let key = "https_probe_\(endpoint.rawValue)_status_0_cause_\(cause)_phase_response_elapsed_ms_\(min(result.elapsedMS, 999_999))"
            budget.record(key)
            // Inspect this site's answer before another site can fail and trigger retry.
            guard address == NativeEnvironmentChecker.expectedIP else {
                throw EnvironmentCheckFailure.probe(key, retryable: false)
            }
            _ = try budget.remainingSeconds()
            return address
        }
    }
}
