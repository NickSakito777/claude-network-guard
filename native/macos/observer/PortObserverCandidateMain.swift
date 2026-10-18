import Darwin
import Foundation

@_silgen_name("cng_observer_install_stop_handlers")
private func installStopHandlers() -> Int32
@_silgen_name("cng_observer_should_stop")
private func stopRequested() -> Int32

@main
struct PortObserverDiagnosticMain {
    static func main() {
        let arguments = Array(CommandLine.arguments.dropFirst())
        if arguments == ["--stdout-watch"], installStopHandlers() != 1 {
            fputs("Unable to install stop handlers\n", stderr)
            exit(70)
        }
        let shouldStop = { stopRequested() != 0 }
        let status = PortObserverRuntime.run(arguments: arguments,
            sample: { PortObserverCandidate.sampleLive() },
            clock: monotonicNow, waitUntil: { deadline in
                waitUntil(deadline, clock: monotonicNow, shouldStop: shouldStop)
            },
            shouldStop: shouldStop,
            writeLine: { line in
                do {
                    try FileHandle.standardOutput.write(contentsOf: line)
                    return true
                } catch { return false }
            },
            diagnostic: { fputs($0 + "\n", stderr) })
        if status != 0 { exit(status) }
    }

    private static func monotonicNow() -> Int64? {
        var value = timespec()
        guard clock_gettime(CLOCK_MONOTONIC, &value) == 0 else { return nil }
        let (seconds, overflow) = Int64(value.tv_sec).multipliedReportingOverflow(by: 1_000_000_000)
        guard !overflow else { return nil }
        let (total, nanoOverflow) = seconds.addingReportingOverflow(Int64(value.tv_nsec))
        return nanoOverflow ? nil : total
    }

    private static func waitUntil(_ deadline: Int64, clock: () -> Int64?,
                                  shouldStop: () -> Bool) {
        while !shouldStop() {
            guard let now = clock(), now < deadline else { return }
            let remaining = deadline - now
            var request = timespec(tv_sec: Int(remaining / 1_000_000_000),
                                   tv_nsec: Int(remaining % 1_000_000_000))
            _ = nanosleep(&request, nil)
        }
    }
}
