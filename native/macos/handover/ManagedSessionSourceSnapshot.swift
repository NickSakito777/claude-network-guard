enum ManagedSessionSourceSnapshot {
    // This freshness snapshot includes the native macOS source tree, Rust host,
    // native Objective-C bridge, app source, scripts, and workflow/build inputs.
    // A matching digest does not prove an inheritance audit passed.
    static let currentKnownUnresolvedEscapePaths: Set<ManagedSessionGateFDEscapePath> = [
        .creationToCloexecRace,
        .unreviewedSpawnPath,
    ]

    // The checker canonicalizes this literal before hashing to avoid recursion.
    static let sha256 = "0cc97ecb3a22847fd35c468574a20dceade609c6a92f3fc6ac409b0e97a3659c"
}
