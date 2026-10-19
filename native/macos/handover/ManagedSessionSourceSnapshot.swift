enum ManagedSessionSourceSnapshot {
    // This freshness snapshot includes the native macOS source tree, Rust host,
    // native Objective-C bridge, app source, scripts, and workflow/build inputs.
    // A matching digest does not prove an inheritance audit passed.
    static let currentKnownUnresolvedEscapePaths: Set<ManagedSessionGateFDEscapePath> = [
        .creationToCloexecRace,
        .unreviewedSpawnPath,
    ]

    // The checker canonicalizes this literal before hashing to avoid recursion.
    static let sha256 = "01d278aee7fb29c6937905c7a8576f7c3d909b023de0ea8a734cec08d337e5bb"
}
