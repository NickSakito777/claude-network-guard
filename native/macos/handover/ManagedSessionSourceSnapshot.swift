enum ManagedSessionSourceSnapshot {
    // This freshness snapshot includes the native macOS source tree, Rust host,
    // native Objective-C bridge, app source, scripts, and workflow/build inputs.
    // A matching digest does not prove an inheritance audit passed.
    static let currentKnownUnresolvedEscapePaths: Set<ManagedSessionGateFDEscapePath> = [
        .creationToCloexecRace,
        .unreviewedSpawnPath,
    ]

    // The checker canonicalizes this literal before hashing to avoid recursion.
    static let sha256 = "e9f3c9810550f2456b385688488fde23eedffaba02a0ea8d676397fb975b6a96"
}
