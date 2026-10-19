import Darwin
import Foundation

@main
enum GateHelperMain {
    static func main() {
        let arguments = CommandLine.arguments
        guard arguments.count > 1 else {
            fputs("Gate helper fixture requires an explicit mode.\n", stderr)
            exit(64)
        }
        switch arguments[1] {
        case "--fixture":
            exit(GateHelperLifecycleFixture.run(executable: arguments[0]))
        case "--helper-child":
            exit(GateHelperChild.runFixtureChild(arguments: Array(arguments.dropFirst())))
        default:
            fputs("Unsupported Gate helper fixture mode.\n", stderr)
            exit(64)
        }
    }
}
