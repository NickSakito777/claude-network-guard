import Foundation
import Darwin
import CryptoKit

enum ProtectedFiles {
    struct Metadata: Equatable {
        let device: UInt64
        let inode: UInt64
        let owner: UInt32
        let group: UInt32
        let mode: UInt32
        let flags: UInt32
        let linkCount: UInt64
        let size: Int64
        let accessSeconds: Int64
        let accessNanoseconds: Int64
        let modificationSeconds: Int64
        let modificationNanoseconds: Int64
        let changeSeconds: Int64
        let changeNanoseconds: Int64

        init(_ value: stat) {
            device = UInt64(value.st_dev)
            inode = UInt64(value.st_ino)
            owner = UInt32(value.st_uid)
            group = UInt32(value.st_gid)
            mode = UInt32(value.st_mode)
            flags = UInt32(value.st_flags)
            linkCount = UInt64(value.st_nlink)
            size = Int64(value.st_size)
            accessSeconds = Int64(value.st_atimespec.tv_sec)
            accessNanoseconds = Int64(value.st_atimespec.tv_nsec)
            modificationSeconds = Int64(value.st_mtimespec.tv_sec)
            modificationNanoseconds = Int64(value.st_mtimespec.tv_nsec)
            changeSeconds = Int64(value.st_ctimespec.tv_sec)
            changeNanoseconds = Int64(value.st_ctimespec.tv_nsec)
        }

        // An access may update only atime. Every identity, permission, size,
        // content-timestamp, and inode-flag field remains security relevant.
        func matchesExceptAccessTime(_ other: Metadata) -> Bool {
            device == other.device && inode == other.inode && owner == other.owner &&
                group == other.group && mode == other.mode && flags == other.flags &&
                linkCount == other.linkCount && size == other.size &&
                modificationSeconds == other.modificationSeconds &&
                modificationNanoseconds == other.modificationNanoseconds &&
                changeSeconds == other.changeSeconds && changeNanoseconds == other.changeNanoseconds
        }
    }

    struct Snapshot {
        let data: Data
        let metadata: Metadata
        let sha256: String
    }

    static func confirmsAtimeOnlyVnodeChange(eventMask: UInt, attribMask: UInt,
                                              metadata: Metadata, sha256: String,
                                              current: Snapshot) -> Bool {
        eventMask == attribMask && metadata.matchesExceptAccessTime(current.metadata) &&
            current.sha256 == sha256
    }

    // Open every component by descriptor; do not follow aliases during a check.
    // Root metadata is required for manifests; content baselines can belong to
    // the interactive user, but their bytes must match the root-pinned hash.
    static func read(_ path: String, maximum: Int, owner: uid_t?) throws -> Data {
        try readSnapshot(path, maximum: maximum, owner: owner).data
    }

    static func readSnapshot(_ path: String, maximum: Int, owner: uid_t?) throws -> Snapshot {
        let parts = path.split(separator: "/").map(String.init)
        guard path.hasPrefix("/"), !parts.isEmpty,
              !parts.contains(".."), !parts.contains(".") else { throw NativeControlError.rejected("file_path") }
        var fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw NativeControlError.unavailable("file_root") }
        defer { close(fd) }
        for (index, component) in parts.enumerated() {
            let last = index == parts.count - 1
            let next = openat(fd, component, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | (last ? 0 : O_DIRECTORY))
            guard next >= 0 else { throw NativeControlError.unavailable("protected_file") }
            close(fd); fd = next
            var info = stat()
            guard fstat(fd, &info) == 0,
                  !last || (info.st_mode & S_IFMT) == S_IFREG,
                  owner == nil || (info.st_uid == owner && info.st_mode & 0o022 == 0) else {
                throw NativeControlError.rejected("file_metadata")
            }
            if last {
                guard info.st_nlink == 1, info.st_size > 0, info.st_size <= maximum else {
                    throw NativeControlError.rejected("file_size")
                }
            }
        }
        var before = stat()
        guard fstat(fd, &before) == 0 else { throw NativeControlError.unavailable("file_stat") }
        var result = Data()
        var buffer = [UInt8](repeating: 0, count: 8192)
        while true {
            let count = Darwin.read(fd, &buffer, buffer.count)
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw NativeControlError.unavailable("file_read") }
            if count == 0 { break }
            guard result.count + count <= maximum else { throw NativeControlError.rejected("file_grew") }
            result.append(contentsOf: buffer.prefix(count))
        }
        var after = stat()
        guard fstat(fd, &after) == 0 else { throw NativeControlError.unavailable("file_stat") }
        let beforeMetadata = Metadata(before)
        let afterMetadata = Metadata(after)
        guard beforeMetadata.matchesExceptAccessTime(afterMetadata),
              Int64(result.count) == beforeMetadata.size,
              Int64(result.count) == afterMetadata.size else {
            throw NativeControlError.rejected("file_changed_during_read")
        }
        let digest = SHA256.hash(data: result).map { String(format: "%02x", $0) }.joined()
        return Snapshot(data: result, metadata: beforeMetadata, sha256: digest)
    }
}
