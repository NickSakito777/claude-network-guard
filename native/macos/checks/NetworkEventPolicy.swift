import Foundation

enum NetworkEventCategory: String, CaseIterable, Hashable {
    case globalAddress = "global_address"
    case globalDNS = "global_dns"
    case globalProxy = "global_proxy"
    case serviceAddress = "service_address"
    case serviceDNS = "service_dns"
    case serviceProxy = "service_proxy"
    case interfaceLink = "interface_link"
    case wifiNetworkName = "wifi_network_name_change"
    case wifiAccessPoint = "wifi_access_point_change"
    case wifiLink = "wifi_link_change"
    case wifiPower = "wifi_power_change"
    case wifiObserverInterrupted = "wifi_observer_interrupted"
    case wifiObserverInvalidated = "wifi_observer_invalidated"
    case notificationUnavailable = "notification_unavailable"
    case unclassifiedNotification = "unclassified_notification"
}

struct NetworkEventScope: Equatable {
    var services: Set<String> = []
    var interfaces: Set<String> = []

    var isUsable: Bool { !services.isEmpty && !interfaces.isEmpty }

    func union(_ other: NetworkEventScope) -> NetworkEventScope {
        NetworkEventScope(services: services.union(other.services),
                          interfaces: interfaces.union(other.interfaces))
    }
}

enum NetworkEventPolicy {
    private static let globalKeys: [String: NetworkEventCategory] = [
        "State:/Network/Global/IPv4": .globalAddress,
        "State:/Network/Global/IPv6": .globalAddress,
        "State:/Network/Global/DNS": .globalDNS,
        "Setup:/Network/Global/DNS": .globalDNS,
        "State:/Network/Global/Proxies": .globalProxy,
        "Setup:/Network/Global/Proxies": .globalProxy,
    ]

    private static let serviceFields: [String: NetworkEventCategory] = [
        "IPv4": .serviceAddress,
        "IPv6": .serviceAddress,
        "DNS": .serviceDNS,
        "Proxies": .serviceProxy,
    ]

    static func subscriptionKeys(scope: NetworkEventScope) -> [String] {
        var keys = Array(globalKeys.keys)
        for service in scope.services where validPathComponent(service) {
            for field in serviceFields.keys {
                keys.append("State:/Network/Service/\(service)/\(field)")
                keys.append("Setup:/Network/Service/\(service)/\(field)")
            }
        }
        for interface in scope.interfaces where validPathComponent(interface) {
            keys.append("State:/Network/Interface/\(interface)/Link")
        }
        return Array(Set(keys)).sorted()
    }

    static func classify(_ keys: [String]?, scope: NetworkEventScope) -> Set<NetworkEventCategory> {
        guard let keys, !keys.isEmpty else {
            return [.unclassifiedNotification]
        }

        var categories = Set<NetworkEventCategory>()
        for key in keys {
            categories.insert(category(for: key, scope: scope) ?? .unclassifiedNotification)
        }
        return categories
    }

    private static func category(for key: String, scope: NetworkEventScope) -> NetworkEventCategory? {
        if let category = globalKeys[key] { return category }
        let parts = key.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 5, parts[1] == "Network" else { return nil }

        if (parts[0] == "State:" || parts[0] == "Setup:"),
           parts[2] == "Service", scope.services.contains(parts[3]),
           validPathComponent(parts[3]) {
            return serviceFields[parts[4]]
        }
        if parts[0] == "State:", parts[2] == "Interface",
           scope.interfaces.contains(parts[3]), validPathComponent(parts[3]),
           parts[4] == "Link" {
            return .interfaceLink
        }
        return nil
    }

    static func validPathComponent(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 128, value != ".", value != ".." else { return false }
        return value.utf8.allSatisfy { byte in
            (48...57).contains(byte) || (65...90).contains(byte) ||
                (97...122).contains(byte) || byte == 45 || byte == 46 || byte == 95
        }
    }

}

enum WiFiAssociationEvent: CaseIterable {
    case networkNameChanged
    case accessPointChanged
    case linkChanged
    case powerChanged
    case observerInterrupted
    case observerInvalidated

    var category: NetworkEventCategory {
        switch self {
        case .networkNameChanged: return .wifiNetworkName
        case .accessPointChanged: return .wifiAccessPoint
        case .linkChanged: return .wifiLink
        case .powerChanged: return .wifiPower
        case .observerInterrupted: return .wifiObserverInterrupted
        case .observerInvalidated: return .wifiObserverInvalidated
        }
    }
}

struct WiFiObserverLifecycle: Equatable {
    private(set) var isLive = false
    private(set) var isUnavailable = false

    mutating func registrationSucceeded() -> Bool {
        guard !isUnavailable else { return false }
        isLive = true
        return true
    }

    mutating func registrationFailed() {
        isLive = false
        isUnavailable = true
    }

    mutating func observerFailed() -> Bool {
        guard !isUnavailable else { return false }
        isLive = false
        isUnavailable = true
        return true
    }
}
