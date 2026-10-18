// [INPUT]: 目标平台、macOS Objective-C 原生/身份凭据桥与 Tauri 配置。
// [OUTPUT]: 仅 macOS 编译链接系统桥；Linux/Windows 使用 Rust 平台边界，各自加载 Tauri 平台配置。
// [POS]: 原生宿主的构建边界。
// [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
#[allow(dead_code)]
#[path = "../scripts/generate-cli-privacy-swift.rs"]
mod privacy_bridge_generator;

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        build_guard_lulu();
        cc::Build::new()
            .file("native/Clipboard.m")
            .file("native/Cleanup.m")
            .file("native/Keychain.m")
            .file("native/Identity.m")
            .file("native/System.m")
            .file("native/Browser.m")
            .flag("-fobjc-arc")
            .compile("selection");
        for framework in [
            "AppKit",
            "UniformTypeIdentifiers",
            "ApplicationServices",
            "Security",
            "LocalAuthentication",
            "CoreLocation",
            "SystemConfiguration",
            "CoreServices",
        ] {
            println!("cargo:rustc-link-lib=framework={framework}");
        }
        println!("cargo:rerun-if-changed=native/Clipboard.m");
        println!("cargo:rerun-if-changed=native/Cleanup.m");
        println!("cargo:rerun-if-changed=native/Keychain.m");
        println!("cargo:rerun-if-changed=native/Identity.m");
        println!("cargo:rerun-if-changed=native/System.m");
        println!("cargo:rerun-if-changed=native/Browser.m");
    }
    tauri_build::build();
}

fn build_guard_lulu() {
    use std::{env, path::PathBuf, process::Command};
    println!("cargo:rerun-if-env-changed=GUARD_OFFLINE_E2E");
    println!("cargo:rustc-check-cfg=cfg(guard_offline_e2e)");
    let offline_e2e = env::var("GUARD_OFFLINE_E2E").as_deref() == Ok("1");
    assert!(!offline_e2e || env::var("PROFILE").as_deref() == Ok("debug"),
        "offline fixture compilation is debug-only");
    if offline_e2e { println!("cargo:rustc-cfg=guard_offline_e2e"); }
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("../native/macos");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let privacy_source = out.join("ManagedPrivacyDefaults.swift");
    privacy_bridge_generator::write_swift(&privacy_source).expect("generate child-only privacy defaults");
    println!("cargo:rerun-if-changed=src/guard_privacy.rs");
    println!("cargo:rerun-if-changed=../scripts/generate-cli-privacy-swift.rs");
    let sdk_output = Command::new("/usr/bin/xcrun").arg("--show-sdk-path").output().expect("read macOS SDK");
    assert!(sdk_output.status.success(), "macOS SDK unavailable");
    let sdk = String::from_utf8(sdk_output.stdout).unwrap().trim().to_owned();
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "aarch64" => "arm64", "x86_64" => "x86_64", other => panic!("unsupported Mac architecture: {other}"),
    };
    let sources = [
        "native/NativeClock.swift", "controller/GuardLuLuContracts.swift", "controller/ProtectedFiles.swift",
        "checks/NetworkEventPolicy.swift", "checks/WiFiAssociationEventMonitor.swift",
        "checks/EnvironmentChecker.swift", "checks/RootPortObserver.swift",
        "handover/SwiftNativeGate.swift", "handover/LegacyApplicationSupervisor.swift",
        "handover/ManagedLaunchCandidate.swift",
        "lulu/LuLuManifest.swift", "lulu/LuLuPolicy.swift", "lulu/LuLuServices.swift",
        "GuardLuLuBridge.swift",
    ];
    let mut command = Command::new("/usr/bin/xcrun");
    command.args(["swiftc", "-parse-as-library", "-emit-library", "-static", "-module-name", "GuardLuLu", "-target"])
        .arg(format!("{arch}-apple-macosx13.0")).args(["-sdk", &sdk, "-module-cache-path"])
        .arg(out.join("swift-modules")).arg("-I").arg(root.join("handover"));
    if offline_e2e {
        command.args(["-D", "GUARD_OFFLINE_E2E", "-D", "GUARD_GATE_FIXTURE_TESTS"]);
        let fixture = root.join("../tests/LuLuOfflineE2EFixture.swift");
        println!("cargo:rerun-if-changed={}", fixture.display());
        command.arg(fixture);
    }
    for source in sources {
        println!("cargo:rerun-if-changed={}", root.join(source).display());
        command.arg(root.join(source));
    }
    command.arg(privacy_source);
    let result = command.arg("-o").arg(out.join("libguard_lulu.a")).output().expect("compile Guard LuLu bridge");
    assert!(result.status.success(), "Swift Guard bridge failed:\n{}", String::from_utf8_lossy(&result.stderr));
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-search=native={sdk}/usr/lib/swift");
    println!("cargo:rustc-link-lib=static=guard_lulu");
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
    let mut native_c = cc::Build::new();
    if offline_e2e { native_c.define("NG_OFFLINE_TEST", None); }
    native_c
        .file(root.join("checks/ObserverIdentity.c"))
        .file(root.join("handover/NativeGate.c"))
        .file(root.join("handover/LegacyProcess.c"))
        .flag("-mmacosx-version-min=13.0")
        .compile("guard_lulu_c");
    println!("cargo:rustc-link-lib=framework=CoreWLAN");
    println!("cargo:rerun-if-changed={}", root.join("handover/module.modulemap").display());
    println!("cargo:rerun-if-changed={}", root.join("handover/LegacyProcess.h").display());
}
