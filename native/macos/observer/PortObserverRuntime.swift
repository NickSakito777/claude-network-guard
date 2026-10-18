import Foundation

enum PortObserverRuntime {
    static let intervalNS: Int64 = 1_000_000_000

    static func run(arguments: [String], sample: () -> Data,
                    clock: () -> Int64?, waitUntil: (Int64) -> Void,
                    shouldStop: () -> Bool, writeLine: (Data) -> Bool,
                    diagnostic: (String) -> Void) -> Int32 {
        guard arguments.count == 1 else {
            diagnostic("Usage: port-observer --stdout-once | --stdout-watch")
            return arguments == ["--help"] ? 0 : 64
        }

        switch arguments[0] {
        case "--stdout-once":
            guard !shouldStop() else { return 0 }
            return emit(sample(), writeLine: writeLine, diagnostic: diagnostic)
        case "--stdout-watch":
            return watch(sample: sample, clock: clock, waitUntil: waitUntil,
                shouldStop: shouldStop, writeLine: writeLine, diagnostic: diagnostic)
        case "--help":
            diagnostic("Usage: port-observer --stdout-once | --stdout-watch")
            return 0
        default:
            diagnostic("Usage: port-observer --stdout-once | --stdout-watch")
            return 64
        }
    }

    private static func watch(sample: () -> Data, clock: () -> Int64?,
                              waitUntil: (Int64) -> Void, shouldStop: () -> Bool,
                              writeLine: (Data) -> Bool,
                              diagnostic: (String) -> Void) -> Int32 {
        if shouldStop() { return 0 }
        guard var nextStart = clock() else {
            diagnostic("monotonic clock unavailable")
            return 70
        }
        while !shouldStop() {
            guard let now = clock() else {
                diagnostic("monotonic clock unavailable")
                return 70
            }
            if now < nextStart {
                waitUntil(nextStart)
                if shouldStop() { return 0 }
                guard let wokeAt = clock(), wokeAt >= nextStart else {
                    diagnostic("monotonic wait did not reach its deadline")
                    return 70
                }
            }
            if shouldStop() { return 0 }
            guard let startedAt = clock() else {
                diagnostic("monotonic clock unavailable")
                return 70
            }
            let data = sample()
            let result = emit(data, writeLine: writeLine, diagnostic: diagnostic)
            guard result == 0 else { return result }
            guard let finishedAt = clock() else {
                diagnostic("monotonic clock unavailable")
                return 70
            }
            let (plannedStart, overflow) = startedAt.addingReportingOverflow(intervalNS)
            if overflow {
                diagnostic("monotonic schedule overflow")
                return 70
            }
            nextStart = max(plannedStart, finishedAt)
        }
        return 0
    }

    private static func emit(_ data: Data, writeLine: (Data) -> Bool,
                             diagnostic: (String) -> Void) -> Int32 {
        guard !data.isEmpty else {
            diagnostic("observer sample serialization failed")
            return 70
        }
        var line = data
        line.append(0x0A)
        guard writeLine(line) else {
            diagnostic("stdout write failed")
            return 74
        }
        return 0
    }
}
