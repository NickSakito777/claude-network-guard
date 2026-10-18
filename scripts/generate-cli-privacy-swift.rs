// One canonical CLI policy feeds both the Rust host and the native child launcher.
#[allow(dead_code)]
#[path = "../src-tauri/src/guard_privacy.rs"]
mod privacy;

pub fn write_swift(path: &std::path::Path) -> std::io::Result<()> {
    let mut set = Vec::new();
    let mut remove = Vec::new();
    for edit in privacy::cli_environment_patch() {
        assert!(edit.key.bytes().all(|c| c.is_ascii_uppercase() || c == b'_'));
        match edit.value {
            Some(value) => {
                assert!(value.bytes().all(|c| c.is_ascii_alphanumeric()));
                set.push(format!("\"{}\": \"{}\"", edit.key, value));
            }
            None => remove.push(format!("\"{}\"", edit.key)),
        }
    }
    std::fs::write(path, format!(
        "// Generated from guard_privacy.rs; do not edit.\nenum ManagedPrivacyDefaults {{\n    static let cliEnvironment: [String: String] = [{}]\n    static let removedKeys: [String] = [{}]\n}}\n",
        set.join(", "), remove.join(", ")))
}

fn main() -> std::io::Result<()> {
    let path = std::env::args_os().nth(1).ok_or_else(|| std::io::Error::other("output path required"))?;
    write_swift(std::path::Path::new(&path))
}
