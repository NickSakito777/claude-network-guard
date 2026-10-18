import Foundation

@main private struct GuardLuLuRenewalTests {
    static func main() {
        let digest = String(repeating: "a", count: 64)
        let upstream = String(repeating: "b", count: 64)
        let ingress = String(repeating: "c", count: 64)
        let fullCheckTime: UInt64 = 1_000_000_000
        let verified = NativeCheckStamp(fingerprint: digest, generation: 7,
            checkedAtNS: fullCheckTime, observedIP: "65.195.109.98", observedAtUnixMS: 1_000,
            upstreamFingerprint: upstream, ingressFingerprint: ingress)
        let unchanged = EnvironmentRenewalSnapshot(networkGeneration: 7,
            upstreamFingerprint: upstream, ingressFingerprint: ingress)
        let renewalTime = fullCheckTime + 50_000_000_000
        precondition(verified.matches(unchanged, checkedAtNS: renewalTime))
        precondition(verified.checkedAtNS == fullCheckTime)
        precondition(verified.observedAtUnixMS == 1_000)
        precondition(verified.hasFreshPublicObservation(at: fullCheckTime + NativeCheckStamp.publicObservationMaxAgeNS))
        precondition(!verified.hasFreshPublicObservation(at: fullCheckTime + NativeCheckStamp.publicObservationMaxAgeNS + 1))
        precondition(!verified.hasFreshPublicObservation(at: fullCheckTime - 1))

        precondition(!verified.matches(EnvironmentRenewalSnapshot(networkGeneration: 8,
            upstreamFingerprint: upstream, ingressFingerprint: ingress), checkedAtNS: renewalTime))
        precondition(!verified.matches(EnvironmentRenewalSnapshot(networkGeneration: 7,
            upstreamFingerprint: String(repeating: "d", count: 64), ingressFingerprint: ingress), checkedAtNS: renewalTime))
        precondition(!verified.matches(EnvironmentRenewalSnapshot(networkGeneration: 7,
            upstreamFingerprint: upstream, ingressFingerprint: String(repeating: "e", count: 64)), checkedAtNS: renewalTime))
        precondition(!verified.matches(unchanged, checkedAtNS: fullCheckTime - 1))
        precondition(LuLuExtensionStatus.isEnabled(in:
            "com.objective-see.lulu.extension [activated enabled]\n"))
        precondition(!LuLuExtensionStatus.isEnabled(in:
            "com.objective-see.lulu.extension [activated disabled]\n"))
        precondition(!LuLuExtensionStatus.isEnabled(in: "no extension found\n"))
        print("Guard LuLu renewal fixtures passed")
    }
}
