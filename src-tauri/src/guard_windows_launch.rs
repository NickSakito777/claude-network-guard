// [INPUT]: Bundle-sealed target specs, a primary token for the dedicated SID, a Guard action lease, and trusted MCP pipes.
// [OUTPUT]: Suspended-to-job Windows launches with final gate checks, identity receipts, and confirmed job cleanup.
// [POS]: Unwired Windows launch candidate; configuration, token, gate, and target acceptance are required before use.
// [PROTOCOL]: Update this header when the launch boundary changes, then check CLAUDE.md.
use crate::{guard::ActionToken, guard_privacy::cli_environment_patch};
use ring::digest::{digest, SHA256};
use serde::Deserialize;
use std::collections::HashMap;

const MAX_SEALED_BYTES: usize = 64 * 1024;
const MAX_COMMAND_LINE_UNITS: usize = 32_767;
const MAX_ARGUMENT_COUNT: usize = 128;
const MAX_ARGUMENT_UNITS: usize = 24_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum LaunchTarget {
    ClaudeCode,
    Mcp,
}

impl LaunchTarget {
    pub(crate) const fn id(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude_code",
            Self::Mcp => "mcp",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "claude_code" => Some(Self::ClaudeCode),
            "mcp" => Some(Self::Mcp),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LaunchError {
    BadSeal,
    InvalidManifest,
    InvalidTarget,
    InvalidSpec,
    IdentityNotVerified,
    GateClosed,
    StaleAction,
    NativeFailure,
    CleanupUnconfirmed,
    TrustedStdioRequired,
    UnexpectedStdio,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ManifestFile {
    schema_version: u8,
    targets: Vec<ManifestTarget>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ManifestTarget {
    id: String,
    executable: String,
    arguments: Vec<String>,
    working_directory: String,
    image_sha256: String,
    dedicated_sid: String,
    stdio_pipes: bool,
}

#[derive(Clone)]
#[derive(Debug)]
struct TargetSpec {
    target: LaunchTarget,
    executable: String,
    arguments: Vec<String>,
    working_directory: String,
    image_sha256: [u8; 32],
    dedicated_sid: String,
    stdio_pipes: bool,
}

#[derive(Debug)]
pub(crate) struct SealedTargets {
    targets: HashMap<LaunchTarget, TargetSpec>,
}

impl SealedTargets {
    /// `trusted_digest` must come from a verified signed bundle resource, not the manifest itself.
    pub(crate) fn decode(bytes: &[u8], trusted_digest: [u8; 32]) -> Result<Self, LaunchError> {
        if bytes.is_empty() || bytes.len() > MAX_SEALED_BYTES {
            return Err(LaunchError::InvalidManifest);
        }
        if digest(&SHA256, bytes).as_ref() != trusted_digest {
            return Err(LaunchError::BadSeal);
        }
        let manifest: ManifestFile =
            serde_json::from_slice(bytes).map_err(|_| LaunchError::InvalidManifest)?;
        if manifest.schema_version != 1 || manifest.targets.is_empty() || manifest.targets.len() > 2 {
            return Err(LaunchError::InvalidManifest);
        }
        let mut targets = HashMap::new();
        for raw in manifest.targets {
            let target = LaunchTarget::parse(&raw.id).ok_or(LaunchError::InvalidTarget)?;
            let spec = TargetSpec::try_from((target, raw))?;
            if targets.insert(target, spec).is_some() {
                return Err(LaunchError::InvalidManifest);
            }
        }
        Ok(Self { targets })
    }

    fn spec(&self, target: LaunchTarget) -> Result<&TargetSpec, LaunchError> {
        self.targets.get(&target).ok_or(LaunchError::InvalidTarget)
    }
}

impl TryFrom<(LaunchTarget, ManifestTarget)> for TargetSpec {
    type Error = LaunchError;

    fn try_from((target, raw): (LaunchTarget, ManifestTarget)) -> Result<Self, Self::Error> {
        if raw.id != target.id()
            || !is_windows_drive_path(&raw.executable)
            || !is_windows_drive_path(&raw.working_directory)
            || !raw.executable.to_ascii_lowercase().ends_with(".exe")
            || rejected_root_command(&raw.executable)
            || !valid_account_sid(&raw.dedicated_sid)
            || raw.arguments.len() > MAX_ARGUMENT_COUNT
            || raw.arguments.iter().any(|arg| arg.contains('\0'))
            || raw.arguments.iter().map(|arg| arg.encode_utf16().count()).sum::<usize>()
                > MAX_ARGUMENT_UNITS
            || (target == LaunchTarget::Mcp && !raw.stdio_pipes)
        {
            return Err(LaunchError::InvalidSpec);
        }
        let image_sha256 = parse_sha256(&raw.image_sha256).ok_or(LaunchError::InvalidSpec)?;
        Ok(Self {
            target,
            executable: raw.executable,
            arguments: raw.arguments,
            working_directory: raw.working_directory,
            image_sha256,
            dedicated_sid: raw.dedicated_sid,
            stdio_pipes: raw.stdio_pipes,
        })
    }
}

fn is_windows_drive_path(value: &str) -> bool {
    let units: Vec<u16> = value.encode_utf16().collect();
    units.len() >= 4
        && is_ascii_letter(units[0])
        && units[1] == b':' as u16
        && units[2] == b'\\' as u16
        && !value.contains('\0')
        && !value.contains('/')
        && !units[2..].contains(&(b':' as u16))
        && !units.iter().any(|unit| *unit < 0x20)
        && !value.split('\\').any(|part| part == ".." || part == ".")
        && !value.contains('%')
}

fn is_ascii_letter(unit: u16) -> bool {
    (b'A' as u16..=b'Z' as u16).contains(&unit) || (b'a' as u16..=b'z' as u16).contains(&unit)
}

fn uppercase_ascii(unit: u16) -> u16 {
    if (b'a' as u16..=b'z' as u16).contains(&unit) {
        unit - (b'a' as u16 - b'A' as u16)
    } else {
        unit
    }
}

fn rejected_root_command(executable: &str) -> bool {
    let name = executable.rsplit('\\').next().unwrap_or(executable);
    matches!(
        name.to_ascii_lowercase().as_str(),
        "cmd.exe"
            | "powershell.exe"
            | "pwsh.exe"
            | "wscript.exe"
            | "cscript.exe"
            | "mshta.exe"
            | "rundll32.exe"
            | "regsvr32.exe"
            | "node.exe"
            | "bun.exe"
            | "python.exe"
            | "pythonw.exe"
            | "bash.exe"
            | "sh.exe"
    )
}

fn parse_sha256(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}

fn valid_account_sid(value: &str) -> bool {
    let mut parts = value.split('-');
    if parts.next() != Some("S") || parts.next() != Some("1") || parts.next() != Some("5") {
        return false;
    }
    let components = parts.collect::<Vec<_>>();
    components.len() == 5
        && components[0] == "21"
        && components.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && part.parse::<u32>().is_ok_and(|value| value.to_string() == *part)
        })
        && components[4].parse::<u32>().is_ok_and(|rid| rid != 0)
}

fn quote_windows_argument(value: &str) -> Vec<u16> {
    let mut quoted = vec![b'"' as u16];
    let mut backslashes = 0usize;
    for unit in value.encode_utf16() {
        match unit {
            unit if unit == b'\\' as u16 => backslashes += 1,
            unit if unit == b'"' as u16 => {
                quoted.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
                quoted.push(unit);
                backslashes = 0;
            }
            unit => {
                quoted.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
                quoted.push(unit);
                backslashes = 0;
            }
        }
    }
    quoted.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
    quoted.push(b'"' as u16);
    quoted
}

fn command_line(executable: &str, arguments: &[String]) -> Result<Vec<u16>, LaunchError> {
    let mut units = quote_windows_argument(executable);
    for argument in arguments {
        units.push(b' ' as u16);
        units.extend(quote_windows_argument(argument));
    }
    if units.len() + 1 > MAX_COMMAND_LINE_UNITS {
        return Err(LaunchError::InvalidSpec);
    }
    units.push(0);
    Ok(units)
}

fn environment_entry_key(entry: &[u16]) -> Option<(&[u16], &[u16])> {
    let first_separator = if entry.first() == Some(&(b'=' as u16)) { 1 } else { 0 };
    let separator = entry
        .iter()
        .enumerate()
        .skip(first_separator)
        .find_map(|(index, unit)| (*unit == b'=' as u16).then_some(index))?;
    Some((&entry[..separator], &entry[separator + 1..]))
}

fn key_matches_ascii(key: &[u16], expected: &str) -> bool {
    key.len() == expected.len()
        && key
            .iter()
            .zip(expected.bytes())
            .all(|(unit, byte)| uppercase_ascii(*unit) == byte.to_ascii_uppercase() as u16)
}

fn apply_cli_privacy_patch(block: &[u16]) -> Result<Vec<u16>, LaunchError> {
    if block.len() < 2 || block.len() > 1_048_576 || block[block.len() - 2..] != [0, 0] {
        return Err(LaunchError::NativeFailure);
    }
    let mut entries = Vec::<Vec<u16>>::new();
    let mut offset = 0usize;
    while offset + 1 < block.len() && block[offset] != 0 {
        let end = block[offset..]
            .iter()
            .position(|unit| *unit == 0)
            .map(|length| offset + length)
            .ok_or(LaunchError::NativeFailure)?;
        let entry = block[offset..end].to_vec();
        if environment_entry_key(&entry).is_none() {
            return Err(LaunchError::NativeFailure);
        }
        entries.push(entry);
        offset = end + 1;
    }
    if offset + 1 != block.len() - 1 && offset + 1 < block.len() {
        return Err(LaunchError::NativeFailure);
    }

    for edit in cli_environment_patch() {
        entries.retain(|entry| {
            !environment_entry_key(entry)
                .is_some_and(|(key, _)| key_matches_ascii(key, edit.key))
        });
        if let Some(value) = edit.value {
            let mut entry = edit.key.encode_utf16().collect::<Vec<_>>();
            entry.push(b'=' as u16);
            entry.extend(value.encode_utf16());
            entries.push(entry);
        }
    }
    entries.sort_by(|left, right| {
        let left = environment_entry_key(left).map(|(key, _)| key).unwrap_or(left);
        let right = environment_entry_key(right).map(|(key, _)| key).unwrap_or(right);
        compare_environment_keys(left, right)
    });
    let mut result = Vec::new();
    for entry in entries {
        result.extend(entry);
        result.push(0);
    }
    result.push(0);
    if result.len() == 1 {
        result.push(0);
    }
    if result.len() > 1_048_576 {
        return Err(LaunchError::InvalidSpec);
    }
    Ok(result)
}

fn compare_environment_keys(left: &[u16], right: &[u16]) -> std::cmp::Ordering {
    left.iter()
        .map(|unit| uppercase_ascii(*unit))
        .cmp(right.iter().map(|unit| uppercase_ascii(*unit)))
}

pub(crate) trait GateReadback {
    fn is_open_for(&self, target: LaunchTarget, generation: u64) -> Result<bool, ()>;
    fn is_closed(&self, target: LaunchTarget) -> Result<bool, ()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LaunchReadback {
    pub(crate) target: LaunchTarget,
    pub(crate) process_id: u32,
    pub(crate) creation_time: u64,
    pub(crate) job_active_processes: u32,
    pub(crate) root_alive: bool,
    pub(crate) image_verified: bool,
}

#[cfg(windows)]
mod native {
    use super::*;
    use ring::digest::Context;
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::path::Path;
    use std::ptr::{null, null_mut};
    use std::thread;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{
        CloseHandle, DuplicateHandle, LocalFree, FILETIME, HANDLE, INVALID_HANDLE_VALUE,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::{
        CheckTokenMembership, DuplicateTokenEx, EqualSid,
        GetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY,
        TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_IMPERSONATE, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TokenElevation,
        TokenElevationType, TokenElevationTypeDefault, TokenImpersonation, TokenPrimary,
        TokenType, TokenUser, SecurityImpersonation, TOKEN_TYPE, TOKEN_USER,
    };
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle, GetFileType, GetFinalPathNameByHandleW,
        ReadFile, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_TYPE_DISK, FILE_TYPE_PIPE, FILE_NAME_NORMALIZED, OPEN_EXISTING,
        VOLUME_NAME_DOS,
    };
    use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicAccountingInformation,
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, QueryInformationJobObject, SetInformationJobObject,
        TerminateJobObject, JobObjectExtendedLimitInformation,
    };
    use windows_sys::Win32::System::Threading::{
        CreateProcessAsUserW, DeleteProcThreadAttributeList,
        GetCurrentProcess, GetProcessId, GetProcessTimes,
        InitializeProcThreadAttributeList, QueryFullProcessImageNameW,
        ResumeThread, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject, CREATE_SUSPENDED,
        CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
        STARTUPINFOEXW, STARTUPINFOW,
    };

    const ADMINISTRATORS_SID: &str = "S-1-5-32-544";
    const MAX_ENVIRONMENT_UNITS: usize = 1_048_576;
    const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
    const JOB_POLL_INTERVAL: Duration = Duration::from_millis(20);

    fn wide_null(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    struct Handle(HANDLE);

    impl Handle {
        fn new(raw: HANDLE) -> Result<Self, LaunchError> {
            if raw.is_null() || raw == INVALID_HANDLE_VALUE {
                Err(LaunchError::NativeFailure)
            } else {
                Ok(Self(raw))
            }
        }
    }

    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                unsafe { CloseHandle(self.0); }
            }
        }
    }

    struct LocalSid(*mut c_void);

    impl LocalSid {
        fn parse(value: &str) -> Result<Self, LaunchError> {
            let mut wide = wide_null(value);
            let mut sid = null_mut();
            if unsafe { ConvertStringSidToSidW(wide.as_mut_ptr(), &mut sid) } == 0 || sid.is_null() {
                return Err(LaunchError::IdentityNotVerified);
            }
            Ok(Self(sid))
        }
    }

    impl Drop for LocalSid {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { LocalFree(self.0.cast()); }
            }
        }
    }

    pub(crate) struct VerifiedPrimaryToken {
        handle: Handle,
        sid: String,
    }

    impl VerifiedPrimaryToken {
        /// The caller must provide a primary token borrowed from an authenticated broker.
        /// This duplicates only that token; it never accepts account names or credentials.
        pub(crate) unsafe fn from_brokered_primary_token(
            token: HANDLE,
            expected_sid: &str,
        ) -> Result<Self, LaunchError> {
            if token.is_null() || token == INVALID_HANDLE_VALUE {
                return Err(LaunchError::IdentityNotVerified);
            }
            Self::verify_and_duplicate(token, expected_sid)
        }

        fn verify_and_duplicate(source: HANDLE, expected_sid: &str) -> Result<Self, LaunchError> {
            if !valid_account_sid(expected_sid) {
                return Err(LaunchError::IdentityNotVerified);
            }
            verify_primary_token(source, expected_sid)?;
            let mut duplicate = null_mut();
            let access = TOKEN_ASSIGN_PRIMARY
                | TOKEN_DUPLICATE
                | TOKEN_QUERY
                | TOKEN_ADJUST_DEFAULT
                | TOKEN_ADJUST_SESSIONID;
            if unsafe {
                DuplicateTokenEx(
                    source,
                    access,
                    null(),
                    SecurityImpersonation,
                    TokenPrimary,
                    &mut duplicate,
                )
            } == 0
            {
                return Err(LaunchError::IdentityNotVerified);
            }
            let handle = Handle::new(duplicate)?;
            verify_primary_token(handle.0, expected_sid)?;
            Ok(Self { handle, sid: expected_sid.to_owned() })
        }

        fn matches(&self, expected_sid: &str) -> bool {
            self.sid == expected_sid && verify_primary_token(self.handle.0, expected_sid).is_ok()
        }
    }

    fn token_information<T: Copy>(
        token: HANDLE,
        information_class: TOKEN_INFORMATION_CLASS,
    ) -> Result<T, LaunchError> {
        let mut value: T = unsafe { zeroed() };
        let mut returned = 0u32;
        if unsafe {
            GetTokenInformation(
                token,
                information_class,
                (&mut value as *mut T).cast(),
                size_of::<T>() as u32,
                &mut returned,
            )
        } == 0 || returned < size_of::<T>() as u32
        {
            return Err(LaunchError::IdentityNotVerified);
        }
        Ok(value)
    }

    fn token_user_buffer(token: HANDLE) -> Result<Vec<usize>, LaunchError> {
        let mut bytes = 0u32;
        let first = unsafe {
            GetTokenInformation(token, TokenUser, null_mut(), 0, &mut bytes)
        };
        if first != 0 || bytes < size_of::<TOKEN_USER>() as u32 || bytes > 64 * 1024 {
            return Err(LaunchError::IdentityNotVerified);
        }
        let mut buffer = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                bytes,
                &mut bytes,
            )
        } == 0
        {
            return Err(LaunchError::IdentityNotVerified);
        }
        Ok(buffer)
    }

    fn token_has_admin_group(token: HANDLE) -> Result<bool, LaunchError> {
        let mut impersonation = null_mut();
        if unsafe {
            DuplicateTokenEx(
                token,
                TOKEN_QUERY | TOKEN_IMPERSONATE,
                null(),
                SecurityImpersonation,
                TokenImpersonation,
                &mut impersonation,
            )
        } == 0
        {
            return Err(LaunchError::IdentityNotVerified);
        }
        let impersonation = Handle::new(impersonation)?;
        let administrators = LocalSid::parse(ADMINISTRATORS_SID)?;
        let mut member = 0;
        if unsafe { CheckTokenMembership(impersonation.0, administrators.0, &mut member) } == 0 {
            return Err(LaunchError::IdentityNotVerified);
        }
        Ok(member != 0)
    }

    fn verify_primary_token(token: HANDLE, expected_sid: &str) -> Result<(), LaunchError> {
        let token_type: TOKEN_TYPE = token_information(token, TokenType)?;
        if token_type != TokenPrimary {
            return Err(LaunchError::IdentityNotVerified);
        }
        let expected = LocalSid::parse(expected_sid)?;
        let user_buffer = token_user_buffer(token)?;
        let user = unsafe { &*user_buffer.as_ptr().cast::<TOKEN_USER>() };
        if user.User.Sid.is_null() || unsafe { EqualSid(user.User.Sid, expected.0) } == 0 {
            return Err(LaunchError::IdentityNotVerified);
        }
        let elevation: TOKEN_ELEVATION = token_information(token, TokenElevation)?;
        let elevation_type: i32 = token_information(token, TokenElevationType)?;
        if elevation.TokenIsElevated != 0
            || elevation_type != TokenElevationTypeDefault
            || token_has_admin_group(token)?
        {
            return Err(LaunchError::IdentityNotVerified);
        }
        Ok(())
    }

    struct UserEnvironment(*mut c_void);

    impl UserEnvironment {
        fn for_token(token: HANDLE) -> Result<Self, LaunchError> {
            let mut block = null_mut();
            if unsafe { CreateEnvironmentBlock(&mut block, token, 0) } == 0 || block.is_null() {
                return Err(LaunchError::NativeFailure);
            }
            Ok(Self(block))
        }

        fn patched(&self) -> Result<Vec<u16>, LaunchError> {
            let block = self.0.cast::<u16>();
            let mut length = 0usize;
            while length + 1 < MAX_ENVIRONMENT_UNITS {
                let first = unsafe { *block.add(length) };
                let second = unsafe { *block.add(length + 1) };
                if first == 0 && second == 0 {
                    let source = unsafe { std::slice::from_raw_parts(block, length + 2) };
                    return apply_cli_privacy_patch(source);
                }
                length += 1;
            }
            Err(LaunchError::InvalidSpec)
        }
    }

    impl Drop for UserEnvironment {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { DestroyEnvironmentBlock(self.0); }
            }
        }
    }

    struct Job(Handle);

    impl Job {
        fn new() -> Result<Self, LaunchError> {
            let raw = unsafe { CreateJobObjectW(null(), null()) };
            let handle = Handle::new(raw)?;
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if unsafe {
                SetInformationJobObject(
                    handle.0,
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            } == 0
            {
                return Err(LaunchError::NativeFailure);
            }
            Ok(Self(handle))
        }

        fn assign(&self, process: HANDLE) -> Result<(), LaunchError> {
            if unsafe { AssignProcessToJobObject(self.0.0, process) } == 0 {
                return Err(LaunchError::NativeFailure);
            }
            Ok(())
        }

        fn active_processes(&self) -> Result<u32, LaunchError> {
            let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
            let mut returned = 0u32;
            if unsafe {
                QueryInformationJobObject(
                    self.0.0,
                    JobObjectBasicAccountingInformation,
                    (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                    size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    &mut returned,
                )
            } == 0 || returned < size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32
            {
                return Err(LaunchError::NativeFailure);
            }
            Ok(info.ActiveProcesses)
        }

        fn terminate(&self) -> Result<(), LaunchError> {
            if unsafe { TerminateJobObject(self.0.0, 1) } == 0 {
                return Err(LaunchError::CleanupUnconfirmed);
            }
            Ok(())
        }
    }

    pub(crate) struct TrustedPipeStdio {
        input: HANDLE,
        output: HANDLE,
        error: HANDLE,
    }

    impl TrustedPipeStdio {
        /// Caller supplies three live, app-owned pipe handles; socket handles are rejected.
        pub(crate) unsafe fn from_pipe_handles(
            input: HANDLE,
            output: HANDLE,
            error: HANDLE,
        ) -> Result<Self, LaunchError> {
            if [input, output, error]
                .iter()
                .any(|handle| {
                    handle.is_null() || unsafe { GetFileType(*handle) } != FILE_TYPE_PIPE
                })
            {
                return Err(LaunchError::UnexpectedStdio);
            }
            Ok(Self { input, output, error })
        }

        fn duplicate(&self) -> Result<[Handle; 3], LaunchError> {
            let source = [self.input, self.output, self.error];
            let mut duplicates = Vec::with_capacity(3);
            for handle in source {
                let mut copy = null_mut();
                if unsafe {
                    DuplicateHandle(
                        GetCurrentProcess(),
                        handle,
                        GetCurrentProcess(),
                        &mut copy,
                        0,
                        1,
                        windows_sys::Win32::Foundation::DUPLICATE_SAME_ACCESS,
                    )
                } == 0
                {
                    return Err(LaunchError::NativeFailure);
                }
                duplicates.push(Handle::new(copy)?);
            }
            let mut duplicates = duplicates.into_iter();
            Ok([
                duplicates.next().ok_or(LaunchError::NativeFailure)?,
                duplicates.next().ok_or(LaunchError::NativeFailure)?,
                duplicates.next().ok_or(LaunchError::NativeFailure)?,
            ])
        }
    }

    struct ProcessAttributes {
        storage: Vec<usize>,
        initialized: bool,
    }

    impl ProcessAttributes {
        fn with_handle_list(handles: &[HANDLE; 3]) -> Result<Self, LaunchError> {
            let mut required = 0usize;
            unsafe {
                InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut required);
            }
            if required == 0 || required > 64 * 1024 {
                return Err(LaunchError::NativeFailure);
            }
            let mut storage = vec![0usize; required.div_ceil(size_of::<usize>())];
            let list = storage.as_mut_ptr().cast();
            if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut required) } == 0 {
                return Err(LaunchError::NativeFailure);
            }
            let mut attributes = Self { storage, initialized: true };
            if unsafe {
                UpdateProcThreadAttribute(
                    attributes.list(),
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    handles.as_ptr().cast(),
                    size_of::<[HANDLE; 3]>(),
                    null_mut(),
                    null(),
                )
            } == 0
            {
                return Err(LaunchError::NativeFailure);
            }
            Ok(attributes)
        }

        fn list(&mut self) -> windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST {
            self.storage.as_mut_ptr().cast()
        }
    }

    impl Drop for ProcessAttributes {
        fn drop(&mut self) {
            if self.initialized {
                unsafe { DeleteProcThreadAttributeList(self.list()); }
            }
        }
    }

    struct LockedImage(Handle);

    impl LockedImage {
        fn open(path: &str, expected: &[u8; 32]) -> Result<Self, LaunchError> {
            let mut wide = wide_null(path);
            let raw = unsafe {
                CreateFileW(
                    wide.as_mut_ptr(),
                    windows_sys::Win32::Foundation::GENERIC_READ,
                    FILE_SHARE_READ,
                    null(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                    null_mut(),
                )
            };
            let handle = Handle::new(raw)?;
            if unsafe { GetFileType(handle.0) } != FILE_TYPE_DISK {
                return Err(LaunchError::InvalidSpec);
            }
            let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
            if unsafe { GetFileInformationByHandle(handle.0, &mut info) } == 0
                || info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
            {
                return Err(LaunchError::InvalidSpec);
            }
            let final_path = final_path(handle.0)?;
            if normalize_windows_path(&final_path) != normalize_windows_path(path) {
                return Err(LaunchError::InvalidSpec);
            }
            let image = Self(handle);
            image.verify_hash(expected)?;
            Ok(image)
        }

        fn verify_hash(&self, expected: &[u8; 32]) -> Result<(), LaunchError> {
            let mut context = Context::new(&SHA256);
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let mut read = 0u32;
                if unsafe {
                    ReadFile(self.0.0, buffer.as_mut_ptr(), buffer.len() as u32, &mut read, null_mut())
                } == 0
                {
                    return Err(LaunchError::NativeFailure);
                }
                if read == 0 {
                    break;
                }
                context.update(&buffer[..read as usize]);
            }
            if context.finish().as_ref() != expected {
                return Err(LaunchError::InvalidSpec);
            }
            Ok(())
        }
    }

    fn final_path(handle: HANDLE) -> Result<String, LaunchError> {
        let flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
        let required = unsafe { GetFinalPathNameByHandleW(handle, null_mut(), 0, flags) };
        if required == 0 || required > 32_768 {
            return Err(LaunchError::NativeFailure);
        }
        let mut buffer = vec![0u16; required as usize + 1];
        let written = unsafe {
            GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, flags)
        };
        if written == 0 || written >= buffer.len() as u32 {
            return Err(LaunchError::NativeFailure);
        }
        String::from_utf16(&buffer[..written as usize]).map_err(|_| LaunchError::NativeFailure)
    }

    fn normalize_windows_path(value: &str) -> String {
        let mut value = value.replace('/', "\\");
        if let Some(rest) = value.strip_prefix("\\\\?\\") {
            value = rest.to_owned();
        }
        value.trim_end_matches('\\').to_ascii_lowercase()
    }

    fn canonical_path(value: &str, directory: bool) -> Result<String, LaunchError> {
        let path = std::fs::canonicalize(Path::new(value)).map_err(|_| LaunchError::InvalidSpec)?;
        if directory && !path.is_dir() || !directory && !path.is_file() {
            return Err(LaunchError::InvalidSpec);
        }
        let result = path.to_str().ok_or(LaunchError::InvalidSpec)?.to_owned();
        if !normalize_windows_path(&result).as_bytes().get(1).is_some_and(|unit| *unit == b':') {
            return Err(LaunchError::InvalidSpec);
        }
        Ok(result)
    }

    struct SpawnedProcess {
        process: Handle,
        thread: Handle,
        pid: u32,
    }

    struct PendingLaunch {
        job: Option<Job>,
        process: Option<Handle>,
        thread: Option<Handle>,
        pid: u32,
        assigned: bool,
        armed: bool,
    }

    impl PendingLaunch {
        fn new(job: Job, process: SpawnedProcess) -> Self {
            Self {
                job: Some(job),
                process: Some(process.process),
                thread: Some(process.thread),
                pid: process.pid,
                assigned: false,
                armed: true,
            }
        }

        fn process(&self) -> HANDLE {
            self.process.as_ref().map(|process| process.0).unwrap_or(null_mut())
        }

        fn job(&self) -> &Job {
            self.job.as_ref().expect("pending job is present")
        }

        fn assign(&mut self) -> Result<(), LaunchError> {
            self.job().assign(self.process())?;
            self.assigned = true;
            Ok(())
        }

        fn abort(mut self, reason: LaunchError) -> LaunchError {
            let confirmed = if self.assigned {
                cleanup_job(self.job(), self.process())
            } else {
                self.process.as_ref().is_some_and(terminate_unassigned)
            };
            self.armed = !confirmed;
            if confirmed { reason } else { LaunchError::CleanupUnconfirmed }
        }

        fn into_parts(mut self) -> (Job, Handle, u32) {
            self.armed = false;
            self.thread.take();
            (
                self.job.take().expect("pending job is present"),
                self.process.take().expect("pending process is present"),
                self.pid,
            )
        }
    }

    impl Drop for PendingLaunch {
        fn drop(&mut self) {
            if !self.armed {
                return;
            }
            if self.assigned {
                let _ = self.job.as_ref().zip(self.process.as_ref()).is_some_and(|(job, process)| {
                    cleanup_job(job, process.0)
                });
            } else if let Some(process) = &self.process {
                let _ = terminate_unassigned(process);
            }
        }
    }

    fn create_suspended_process(
        token: &VerifiedPrimaryToken,
        executable: &str,
        command: &mut [u16],
        directory: &str,
        environment: &[u16],
        stdio: Option<&TrustedPipeStdio>,
    ) -> Result<SpawnedProcess, LaunchError> {
        let executable = wide_null(executable);
        let directory = wide_null(directory);
        let copies = stdio.map(TrustedPipeStdio::duplicate).transpose()?;
        let child_handles = copies.as_ref().map(|copies| [copies[0].0, copies[1].0, copies[2].0]);
        let mut attributes = child_handles
            .as_ref()
            .map(ProcessAttributes::with_handle_list)
            .transpose()?;
        let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
        let mut flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;
        let inherit_handles = if let (Some(handles), Some(attributes)) = (child_handles, attributes.as_mut()) {
            startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
            startup.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdInput = handles[0];
            startup.StartupInfo.hStdOutput = handles[1];
            startup.StartupInfo.hStdError = handles[2];
            startup.lpAttributeList = attributes.list();
            flags |= EXTENDED_STARTUPINFO_PRESENT;
            1
        } else {
            startup.StartupInfo.cb = size_of::<STARTUPINFOW>() as u32;
            0
        };
        let mut process_info: PROCESS_INFORMATION = unsafe { zeroed() };
        let created = unsafe {
            CreateProcessAsUserW(
                token.handle.0,
                executable.as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                inherit_handles,
                flags,
                environment.as_ptr().cast(),
                directory.as_ptr(),
                &startup.StartupInfo,
                &mut process_info,
            )
        };
        if created == 0 {
            return Err(LaunchError::NativeFailure);
        }
        if process_info.hProcess.is_null() || process_info.hThread.is_null() || process_info.dwProcessId == 0 {
            if !process_info.hProcess.is_null() {
                unsafe { TerminateProcess(process_info.hProcess, 1); }
                unsafe { WaitForSingleObject(process_info.hProcess, CLEANUP_TIMEOUT.as_millis() as u32); }
                unsafe { CloseHandle(process_info.hProcess); }
            }
            if !process_info.hThread.is_null() {
                unsafe { CloseHandle(process_info.hThread); }
            }
            return Err(LaunchError::CleanupUnconfirmed);
        }
        Ok(SpawnedProcess {
            process: Handle::new(process_info.hProcess)?,
            thread: Handle::new(process_info.hThread)?,
            pid: process_info.dwProcessId,
        })
    }

    fn process_creation_time(process: HANDLE) -> Result<u64, LaunchError> {
        let [mut created, mut exited, mut kernel, mut user] = [FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        }; 4];
        if unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
            return Err(LaunchError::NativeFailure);
        }
        Ok((created.dwHighDateTime as u64) << 32 | created.dwLowDateTime as u64)
    }

    fn process_image(process: HANDLE) -> Result<String, LaunchError> {
        let mut buffer = vec![0u16; 32_768];
        let mut length = buffer.len() as u32;
        if unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut length) } == 0
            || length as usize > buffer.len()
        {
            return Err(LaunchError::NativeFailure);
        }
        String::from_utf16(&buffer[..length as usize]).map_err(|_| LaunchError::NativeFailure)
    }

    fn process_is_alive(process: HANDLE) -> Result<bool, LaunchError> {
        match unsafe { WaitForSingleObject(process, 0) } {
            WAIT_TIMEOUT => Ok(true),
            WAIT_OBJECT_0 => Ok(false),
            _ => Err(LaunchError::NativeFailure),
        }
    }

    fn process_identity(
        process: HANDLE,
        expected_pid: u32,
        expected_creation_time: u64,
        expected_image: &str,
    ) -> Result<(u64, bool), LaunchError> {
        if unsafe { GetProcessId(process) } != expected_pid {
            return Err(LaunchError::NativeFailure);
        }
        let created = process_creation_time(process)?;
        if created != expected_creation_time {
            return Err(LaunchError::NativeFailure);
        }
        let alive = process_is_alive(process)?;
        if alive && normalize_windows_path(&process_image(process)?) != normalize_windows_path(expected_image) {
            return Err(LaunchError::NativeFailure);
        }
        Ok((created, alive))
    }

    fn terminate_unassigned(process: &Handle) -> bool {
        let _ = unsafe { TerminateProcess(process.0, 1) };
        (unsafe { WaitForSingleObject(process.0, CLEANUP_TIMEOUT.as_millis() as u32) })
            == WAIT_OBJECT_0
    }

    fn cleanup_job(job: &Job, process: HANDLE) -> bool {
        let _ = job.terminate();
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        loop {
            let root_exited = matches!(unsafe { WaitForSingleObject(process, 0) }, WAIT_OBJECT_0);
            let empty = job.active_processes().is_ok_and(|count| count == 0);
            if root_exited && empty {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(JOB_POLL_INTERVAL);
        }
    }

    pub(crate) struct ManagedLauncher {
        targets: SealedTargets,
    }

    impl ManagedLauncher {
        pub(crate) fn new(targets: SealedTargets) -> Self {
            Self { targets }
        }

        pub(crate) fn start(
            &self,
            target: LaunchTarget,
            token: &VerifiedPrimaryToken,
            action: &ActionToken,
            gate: &dyn GateReadback,
            stdio: Option<&TrustedPipeStdio>,
        ) -> Result<OwnedLaunch, LaunchError> {
            let spec = self.targets.spec(target)?;
            if spec.target != target || token.sid != spec.dedicated_sid || !token.matches(&spec.dedicated_sid) {
                return Err(LaunchError::IdentityNotVerified);
            }
            if spec.stdio_pipes != stdio.is_some() {
                return Err(if spec.stdio_pipes { LaunchError::TrustedStdioRequired } else { LaunchError::UnexpectedStdio });
            }
            if !action.is_current() {
                return Err(LaunchError::StaleAction);
            }
            if !gate.is_open_for(target, action.generation()).unwrap_or(false) {
                return Err(LaunchError::GateClosed);
            }
            let executable = canonical_path(&spec.executable, false)?;
            let directory = canonical_path(&spec.working_directory, true)?;
            let _image_lock = LockedImage::open(&executable, &spec.image_sha256)?;
            let environment_owner = UserEnvironment::for_token(token.handle.0)?;
            let environment = environment_owner.patched()?;
            let mut command = command_line(&executable, &spec.arguments)?;

            let job = Job::new()?;
            let spawned = create_suspended_process(
                token,
                &executable,
                &mut command,
                &directory,
                &environment,
                stdio,
            )?;
            let mut pending = PendingLaunch::new(job, spawned);
            let creation_time = match process_creation_time(pending.process()) {
                Ok(value) => value,
                Err(error) => return Err(pending.abort(error)),
            };
            if let Err(error) = pending.assign() {
                return Err(pending.abort(error));
            }

            let active = match pending.job().active_processes() {
                Ok(value) => value,
                Err(error) => return Err(pending.abort(error)),
            };
            let image_matches = process_image(pending.process())
                .is_ok_and(|image| normalize_windows_path(&image) == normalize_windows_path(&executable));
            let identity_ok = active == 1
                && unsafe { GetProcessId(pending.process()) } == pending.pid
                && image_matches
                && process_creation_time(pending.process()).is_ok_and(|created| created == creation_time)
                && process_is_alive(pending.process()).unwrap_or(false);
            if !identity_ok {
                return Err(pending.abort(LaunchError::NativeFailure));
            }
            if LockedImage::open(&executable, &spec.image_sha256).is_err() {
                return Err(pending.abort(LaunchError::InvalidSpec));
            }
            if !action.is_current() {
                return Err(pending.abort(LaunchError::StaleAction));
            }
            if !gate.is_open_for(target, action.generation()).unwrap_or(false) {
                return Err(pending.abort(LaunchError::GateClosed));
            }
            let thread = pending.thread.as_ref().map(|thread| thread.0).unwrap_or(null_mut());
            if unsafe { ResumeThread(thread) } != 1 {
                return Err(pending.abort(LaunchError::NativeFailure));
            }
            let identity = process_identity(
                pending.process(),
                pending.pid,
                creation_time,
                &executable,
            );
            let active = pending.job().active_processes();
            let reason = if !action.is_current() {
                Some(LaunchError::StaleAction)
            } else if !gate.is_open_for(target, action.generation()).unwrap_or(false) {
                Some(LaunchError::GateClosed)
            } else if !identity.is_ok_and(|(_, alive)| alive) || !active.is_ok_and(|count| count > 0) {
                Some(LaunchError::NativeFailure)
            } else {
                None
            };
            if let Some(reason) = reason {
                return Err(pending.abort(reason));
            }
            let (job, process, process_id) = pending.into_parts();
            Ok(OwnedLaunch {
                job,
                process,
                target,
                generation: action.generation(),
                process_id,
                creation_time,
                image_path: executable,
                image_verified: true,
            })
        }
    }

    pub(crate) struct OwnedLaunch {
        job: Job,
        process: Handle,
        target: LaunchTarget,
        generation: u64,
        process_id: u32,
        creation_time: u64,
        image_path: String,
        image_verified: bool,
    }

    impl OwnedLaunch {
        pub(crate) fn generation(&self) -> u64 {
            self.generation
        }

        pub(crate) fn readback(&self) -> Result<LaunchReadback, LaunchError> {
            let (created, root_alive) = process_identity(
                self.process.0,
                self.process_id,
                self.creation_time,
                &self.image_path,
            )?;
            let active = self.job.active_processes()?;
            if root_alive && active == 0 {
                return Err(LaunchError::CleanupUnconfirmed);
            }
            Ok(LaunchReadback {
                target: self.target,
                process_id: self.process_id,
                creation_time: created,
                job_active_processes: active,
                root_alive,
                image_verified: self.image_verified,
            })
        }

        pub(crate) fn stop(&mut self, gate: &dyn GateReadback) -> Result<LaunchReadback, LaunchError> {
            if !gate.is_closed(self.target).unwrap_or(false) {
                return Err(LaunchError::GateClosed);
            }
            let _ = self.job.terminate();
            let deadline = Instant::now() + CLEANUP_TIMEOUT;
            loop {
                let root_alive = process_is_alive(self.process.0).unwrap_or(true);
                let active = self.job.active_processes();
                if root_alive && active == Ok(0) {
                    let _ = unsafe { TerminateProcess(self.process.0, 1) };
                }
                if !root_alive && active == Ok(0) {
                    return Ok(LaunchReadback {
                        target: self.target,
                        process_id: self.process_id,
                        creation_time: self.creation_time,
                        job_active_processes: 0,
                        root_alive: false,
                        image_verified: self.image_verified,
                    });
                }
                if Instant::now() >= deadline {
                    return Err(LaunchError::CleanupUnconfirmed);
                }
                thread::sleep(JOB_POLL_INTERVAL);
            }
        }
    }
}

#[cfg(windows)]
pub(crate) use native::{ManagedLauncher, OwnedLaunch, TrustedPipeStdio, VerifiedPrimaryToken};

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &[u8] = include_bytes!("guard_windows_launch/fixtures/targets.valid.json");

    fn sealed(bytes: &[u8]) -> SealedTargets {
        SealedTargets::decode(bytes, digest(&SHA256, bytes).as_ref().try_into().unwrap()).unwrap()
    }

    #[test]
    fn sealed_configuration_yields_only_fixed_targets_and_rejects_tampering() {
        let config = sealed(VALID);
        assert!(config.spec(LaunchTarget::ClaudeCode).is_ok());
        assert!(config.spec(LaunchTarget::Mcp).is_ok());
        assert_eq!(LaunchTarget::parse("cmd.exe"), None);

        let mut modified = VALID.to_vec();
        modified.push(b' ');
        assert!(matches!(
            SealedTargets::decode(&modified, digest(&SHA256, VALID).as_ref().try_into().unwrap()),
            Err(LaunchError::BadSeal)
        ));
    }

    #[test]
    fn sealed_specs_reject_shells_relative_paths_and_missing_mcp_pipes() {
        for (executable, working_directory, stdio_pipes) in [
            ("C:\\Windows\\System32\\cmd.exe", "C:\\Guard", false),
            ("relative\\claude.exe", "C:\\Guard", false),
            ("C:\\Guard\\mcp.exe", "C:\\Guard", false),
        ] {
            let target = ManifestTarget {
                id: "mcp".into(),
                executable: executable.into(),
                arguments: vec![],
                working_directory: working_directory.into(),
                image_sha256: "00".repeat(32),
                dedicated_sid: "S-1-5-21-1-2-3-1001".into(),
                stdio_pipes,
            };
            assert_eq!(TargetSpec::try_from((LaunchTarget::Mcp, target)).unwrap_err(), LaunchError::InvalidSpec);
        }
    }

    #[test]
    fn privacy_patch_changes_only_the_child_environment_block() {
        let input = [
            "=C:=C:\\Guard".encode_utf16().collect::<Vec<_>>(),
            "Path=C:\\Windows".encode_utf16().collect(),
            "claude_code_disable_nonessential_traffic=0".encode_utf16().collect(),
            "ENABLE_BETA_TRACING_DETAILED=1".encode_utf16().collect(),
            "OTEL_EXPORTER_OTLP_ENDPOINT=https://private.invalid".encode_utf16().collect(),
        ];
        let mut block = Vec::new();
        for entry in &input {
            block.extend(entry);
            block.push(0);
        }
        block.push(0);

        let patched = apply_cli_privacy_patch(&block).unwrap();
        let mut entries = Vec::new();
        let mut offset = 0;
        while offset + 1 < patched.len() && patched[offset] != 0 {
            let end = patched[offset..].iter().position(|unit| *unit == 0).unwrap() + offset;
            entries.push(String::from_utf16(&patched[offset..end]).unwrap());
            offset = end + 1;
        }
        for edit in cli_environment_patch() {
            let values = entries
                .iter()
                .filter_map(|entry| environment_entry_key(&entry.encode_utf16().collect::<Vec<_>>()).map(|(key, value)| (key.to_vec(), value.to_vec())))
                .filter(|(key, _)| key_matches_ascii(key, edit.key))
                .map(|(_, value)| String::from_utf16(&value).unwrap())
                .collect::<Vec<_>>();
            match edit.value {
                Some(value) => assert_eq!(values, [value]),
                None => assert!(values.is_empty()),
            }
        }
        assert!(entries.iter().any(|entry| entry == "=C:=C:\\Guard"));
        assert!(entries.iter().any(|entry| entry == "OTEL_EXPORTER_OTLP_ENDPOINT=https://private.invalid"));
    }

    #[test]
    fn command_line_uses_windows_argument_quoting_without_shell_text() {
        let line = command_line(
            "C:\\Guard Tools\\claude.exe",
            &["space here".into(), "quote\"inside".into(), "trailing\\".into()],
        )
        .unwrap();
        let line = String::from_utf16(&line[..line.len() - 1]).unwrap();
        assert_eq!(line, r#""C:\Guard Tools\claude.exe" "space here" "quote\"inside" "trailing\\""#);
    }

    #[test]
    fn managed_sid_must_be_a_nonzero_dedicated_account_rid() {
        assert!(valid_account_sid("S-1-5-21-1-2-3-1001"));
        assert!(!valid_account_sid("S-1-5-18"));
        assert!(!valid_account_sid("S-1-5-21-1-2-3-0"));
        assert!(!valid_account_sid("S-1-5-21-1-2-3-x"));
    }
}
