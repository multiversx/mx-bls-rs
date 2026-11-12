use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=executors");

    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();

    // Absolute path: rustc does not run in the package directory when this
    // crate is a workspace member, so a relative path would not be found.
    let executors = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("executors");

    // System libraries are listed after the archive that depends on them,
    // which GNU ld requires.
    let (lib, system_libs): (&str, &[&str]) = match (arch.as_str(), os.as_str()) {
        ("x86_64", "linux") => ("bls384_256_amd_linux", &["stdc++"]),
        ("aarch64", "linux") => ("bls384_256_arm_linux", &["stdc++"]),
        ("x86_64", "macos") => ("bls384_256_amd_macos", &["c++"]),
        ("aarch64", "macos") => ("bls384_256_arm_macos", &["c++"]),
        ("x86_64", "windows") => {
            let env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
            if env == "msvc" {
                panic!(
                    "The x86_64-pc-windows-msvc target is not supported: only a MinGW/GNU-compatible \
                     static archive is provided. Use the x86_64-pc-windows-gnu target instead, or \
                     supply an MSVC-compatible import/static library."
                );
            }
            ("bls384_256_amd_windows", &["advapi32", "stdc++"])
        }
        _ => panic!("Unsupported target: {os}-{arch}"),
    };

    println!("cargo:rustc-link-search=native={}", executors.display());
    println!("cargo:rustc-link-lib=static={lib}");
    for system_lib in system_libs {
        println!("cargo:rustc-link-lib={system_lib}");
    }
}
