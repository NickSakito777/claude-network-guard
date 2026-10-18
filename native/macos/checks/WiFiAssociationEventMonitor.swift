import CoreWLAN
import Foundation

enum WiFiAssociationMonitorError: Error {
    case registrationFailed
    case interruptedDuringRegistration
}

final class WiFiAssociationEventMonitor: NSObject, CWEventDelegate {
    private let client: CWWiFiClient
    private let onEvent: (WiFiAssociationEvent) -> Void
    private let stateLock = NSLock()
    private var lifecycle = WiFiObserverLifecycle()

    // Live means registration returned successfully and no later connection
    // failure was observed. It is not evidence that macOS delivered an event.
    var isLive: Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return lifecycle.isLive
    }

    init(onEvent: @escaping (WiFiAssociationEvent) -> Void) throws {
        client = CWWiFiClient()
        self.onEvent = onEvent
        super.init()
        client.delegate = self

        do {
            try client.startMonitoringEvent(with: .ssidDidChange)
            try client.startMonitoringEvent(with: .bssidDidChange)
            try client.startMonitoringEvent(with: .linkDidChange)
            try client.startMonitoringEvent(with: .powerDidChange)
        } catch {
            try? client.stopMonitoringAllEvents()
            client.delegate = nil
            stateLock.lock()
            lifecycle.registrationFailed()
            stateLock.unlock()
            throw WiFiAssociationMonitorError.registrationFailed
        }

        stateLock.lock()
        let registrationSurvived = lifecycle.registrationSucceeded()
        stateLock.unlock()
        guard registrationSurvived else {
            try? client.stopMonitoringAllEvents()
            client.delegate = nil
            throw WiFiAssociationMonitorError.interruptedDuringRegistration
        }
    }

    deinit {
        try? client.stopMonitoringAllEvents()
        client.delegate = nil
    }

    private func emit(_ event: WiFiAssociationEvent) {
        onEvent(event)
    }

    private func markUnavailable(_ event: WiFiAssociationEvent) {
        stateLock.lock()
        let shouldNotify = lifecycle.observerFailed()
        stateLock.unlock()
        if shouldNotify { emit(event) }
    }

    func ssidDidChangeForWiFiInterface(withName name: String) {
        emit(.networkNameChanged)
    }

    func bssidDidChangeForWiFiInterface(withName name: String) {
        emit(.accessPointChanged)
    }

    func linkDidChangeForWiFiInterface(withName name: String) {
        emit(.linkChanged)
    }

    func powerStateDidChangeForWiFiInterface(withName name: String) {
        emit(.powerChanged)
    }

    func clientConnectionInterrupted() {
        markUnavailable(.observerInterrupted)
    }

    func clientConnectionInvalidated() {
        markUnavailable(.observerInvalidated)
    }
}
