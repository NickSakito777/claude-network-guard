import Foundation

@main
struct PortObserverRuntimeTests {
    static func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
        guard condition() else { fatalError("FAIL: \(message)") }
        print("PASS: \(message)")
    }

    static func run(_ args: [String], sample: @escaping () -> Data,
                    clock: @escaping () -> Int64? = { 0 },
                    waitUntil: @escaping (Int64) -> Void = { _ in },
                    shouldStop: @escaping () -> Bool = { false },
                    writeLine: @escaping (Data) -> Bool,
                    diagnostic: @escaping (String) -> Void = { _ in }) -> Int32 {
        PortObserverRuntime.run(arguments: args, sample: sample, clock: clock,
            waitUntil: waitUntil, shouldStop: shouldStop, writeLine: writeLine,
            diagnostic: diagnostic)
    }

    static func main() {
        let json = Data("{\"ok\":true}".utf8)
        var samples = 0
        var output: [Data] = []
        var diagnostics: [String] = []

        let noMode = run([], sample: { samples += 1; return json },
            writeLine: { output.append($0); return true }, diagnostic: { diagnostics.append($0) })
        expect(noMode == 64 && samples == 0 && output.isEmpty,
               "no mode is a usage error and does not sample or write")

        let help = run(["--help"], sample: { samples += 1; return json },
            writeLine: { output.append($0); return true }, diagnostic: { diagnostics.append($0) })
        expect(help == 0 && samples == 0 && output.isEmpty,
               "help is read-only and does not sample")

        output.removeAll()
        let once = run(["--stdout-once"], sample: { samples += 1; return json },
            writeLine: { output.append($0); return true })
        expect(once == 0 && samples == 1 && output == [Data("{\"ok\":true}\n".utf8)],
               "stdout-once emits exactly one newline-terminated JSON record")

        samples = 0
        output.removeAll()
        var now: Int64 = 0
        var stop = false
        var starts: [Int64] = []
        var deadlines: [Int64] = []
        let periodic = run(["--stdout-watch"], sample: {
            starts.append(now)
            samples += 1
            now += 100_000_000
            if samples == 2 { stop = true }
            return json
        }, clock: { now }, waitUntil: { deadline in deadlines.append(deadline); now = deadline },
            shouldStop: { stop }, writeLine: { output.append($0); return true })
        expect(periodic == 0 && starts == [0, 1_000_000_000] &&
               deadlines == [1_000_000_000] && output.count == 2,
               "watch schedules one serial sample per second and stops cleanly")

        now = 0
        stop = false
        starts.removeAll()
        deadlines.removeAll()
        samples = 0
        let overrun = run(["--stdout-watch"], sample: {
            starts.append(now)
            samples += 1
            now += 2_000_000_000
            if samples == 2 { stop = true }
            return json
        }, clock: { now }, waitUntil: { deadline in deadlines.append(deadline); now = deadline },
            shouldStop: { stop }, writeLine: { _ in true })
        expect(overrun == 0 && starts == [0, 2_000_000_000] && deadlines.isEmpty,
               "slow sample is never overlapped or replayed to catch up")

        now = 0
        stop = false
        samples = 0
        output.removeAll()
        let stoppedInWait = run(["--stdout-watch"], sample: {
            samples += 1
            now += 100_000_000
            return json
        }, clock: { now }, waitUntil: { _ in stop = true }, shouldStop: { stop },
            writeLine: { output.append($0); return true })
        expect(stoppedInWait == 0 && samples == 1 && output.count == 1,
               "stop request during cadence wait prevents the next sample")

        samples = 0
        output.removeAll()
        let failedWrite = run(["--stdout-watch"], sample: { samples += 1; return json },
            writeLine: { _ in false })
        expect(failedWrite == 74 && samples == 1 && output.isEmpty,
               "stdout write failure stops without retrying or sampling again")

        samples = 0
        var clockReads = 0
        let failedClock = run(["--stdout-watch"], sample: { samples += 1; return json },
            clock: { clockReads += 1; return nil }, writeLine: { _ in true })
        expect(failedClock == 70 && samples == 0,
               "unavailable injected clock stops before any sample")

        samples = 0
        var emptyWrites = 0
        let emptySample = run(["--stdout-once"], sample: { samples += 1; return Data() },
            writeLine: { _ in emptyWrites += 1; return true })
        expect(emptySample == 70 && samples == 1 && emptyWrites == 0,
               "empty serialization fails closed without an output record")

        stop = true
        samples = 0
        let stoppedBeforeStart = run(["--stdout-watch"], sample: { samples += 1; return json },
            shouldStop: { stop }, writeLine: { _ in true })
        expect(stoppedBeforeStart == 0 && samples == 0,
               "preexisting stop request exits before sampling")
    }
}
