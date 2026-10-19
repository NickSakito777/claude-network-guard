// [INPUT]: 目标平台、macOS 原生桥、独立 Gate helper 与 Tauri 配置。
// [OUTPUT]: macOS 构建静态系统桥及未接入应用的 helper 工件；Linux/Windows 使用各自平台边界。
// [POS]: 原生宿主的构建边界。
// [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
#[allow(dead_code)]
#[path = "../scripts/generate-cli-privacy-swift.rs"]
mod privacy_bridge_generator;

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        build_guard_lulu();
        build_guard_gate_helper();
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

// Compile the per-session Gate owner as a standalone executable. The app-side
// controller is linked separately and addresses only its inherited control FD.
fn build_guard_gate_helper() {
    use std::{env, fs, path::PathBuf, process::Command};

    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let root = manifest.join("../native/macos");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let modules = out.join("gate-helper-swift-modules");
    fs::create_dir_all(&modules).expect("create standalone Gate helper Swift cache");
    let sdk_output = Command::new("/usr/bin/xcrun")
        .args(["--show-sdk-path"])
        .output()
        .expect("read macOS SDK for standalone Gate helper");
    assert!(sdk_output.status.success(), "macOS SDK unavailable for Gate helper");
    let sdk = String::from_utf8(sdk_output.stdout).unwrap().trim().to_owned();
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        other => panic!("unsupported Mac architecture for Gate helper: {other}"),
    };
    let target = format!("{arch}-apple-macosx13.0");
    let native_gate = root.join("handover/NativeGate.c");
    let native_header = root.join("handover/NativeGate.h");
    let c_object = out.join("NativeGate-gate-helper.o");
    let helper = out.join("guard-gate-helper");

    println!("cargo:rerun-if-changed={}", native_gate.display());
    println!("cargo:rerun-if-changed={}", native_header.display());
    for source in [
        "handover/GateHelperIPC.swift",
        "handover/GateHelperProduction.swift",
        "handover/GateHelperMain.swift",
    ] {
        println!("cargo:rerun-if-changed={}", root.join(source).display());
    }

    let clang = Command::new("/usr/bin/xcrun")
        .args(["clang", "-std=c11", "-target", &target, "-isysroot", &sdk,
               "-mmacosx-version-min=13.0", "-Wall", "-Wextra", "-Werror", "-pthread", "-I"])
        .arg(root.join("handover"))
        .args(["-c"])
        .arg(&native_gate)
        .arg("-o")
        .arg(&c_object)
        .output()
        .expect("compile standalone NativeGate helper object");
    assert!(clang.status.success(), "NativeGate helper compile failed:\n{}",
            String::from_utf8_lossy(&clang.stderr));

    let swift = Command::new("/usr/bin/xcrun")
        .args(["swiftc", "-parse-as-library", "-emit-executable", "-target", &target,
               "-sdk", &sdk, "-module-cache-path"])
        .arg(&modules)
        .arg("-I")
        .arg(root.join("handover"))
        .arg(root.join("handover/GateHelperIPC.swift"))
        .arg(root.join("handover/GateHelperProduction.swift"))
        .arg(root.join("handover/GateHelperMain.swift"))
        .arg(&c_object)
        .arg("-o")
        .arg(&helper)
        .output()
        .expect("compile standalone Gate helper executable");
    assert!(swift.status.success(), "Gate helper Swift compile failed:\n{}",
            String::from_utf8_lossy(&swift.stderr));
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
        "handover/GateHelperIPC.swift", "handover/GateHelperHost.swift",
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
