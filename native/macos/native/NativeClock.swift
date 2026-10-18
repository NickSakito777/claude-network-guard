import Darwin

enum NativeContinuousClock {
    // Unlike uptime clocks, mach_continuous_time includes time spent asleep.
    // The future policy authority must use this same boot-scoped nanosecond base.
    static func nowNS() -> UInt64? {
        var base = mach_timebase_info_data_t()
        guard mach_timebase_info(&base) == KERN_SUCCESS, base.denom != 0 else { return nil }
        let parts = mach_continuous_time().quotientAndRemainder(dividingBy: UInt64(base.denom))
        let whole = parts.quotient.multipliedReportingOverflow(by: UInt64(base.numer))
        let remainder = parts.remainder.multipliedReportingOverflow(by: UInt64(base.numer))
        guard !whole.overflow, !remainder.overflow else { return nil }
        let total = whole.partialValue.addingReportingOverflow(remainder.partialValue / UInt64(base.denom))
        return total.overflow ? nil : total.partialValue
    }
}
