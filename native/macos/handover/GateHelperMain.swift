import Darwin
import Foundation

@main
enum GateHelperMain {
    static func main() {
        let arguments = CommandLine.arguments
#if GUARD_GATE_FIXTURE_TESTS
#if GUARD_GATE_HOST_FIXTURE_TESTS
        if arguments.count == 1 {
            exit(GateHelperProductionServer.runInheritedControlFD(
                GateHelperProductionPolicy.controlDescriptor
            ))
        }
#endif
        guard arguments.count > 1 else {
            fputs("Gate helper fixture requires an explicit mode.\n", stderr)
            exit(64)
        }
        switch arguments[1] {
        case "--fixture":
            let lifecycle = GateHelperLifecycleFixture.run(executable: arguments[0])
            let production = GateHelperProductionFixture.run(executable: arguments[0])
            exit(lifecycle == 0 && production == 0 ? 0 : 1)
        case "--helper-child":
            exit(GateHelperChild.runFixtureChild(arguments: Array(arguments.dropFirst())))
        case "--production-fixture-child":
            exit(GateHelperProductionServer.runFixtureChild(arguments: Array(arguments.dropFirst(2))))
        default:
            fputs("Unsupported Gate helper fixture mode.\n", stderr)
            exit(64)
        }
#else
        guard arguments.count == 1 else {
            fputs("Gate helper accepts no runtime arguments.\n", stderr)
            exit(64)
        }
        exit(GateHelperProductionServer.runInheritedControlFD(
            GateHelperProductionPolicy.controlDescriptor
        ))
#endif
    }
}
