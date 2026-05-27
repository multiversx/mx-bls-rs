fn main() {
    let target = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();

    match (target.as_str(), os.as_str()) {
        ("x86_64", "linux") => {
            println!("cargo:rustc-link-search=native=./executors");
            println!("cargo:rustc-link-lib=static=bls384_256_amd_linux");
            println!("cargo:rustc-link-lib=stdc++");
        }
        ("aarch64", "linux") | ("arm", "linux") => {
            println!("cargo:rustc-link-search=native=./executors");
            println!("cargo:rustc-link-lib=static=bls384_256_arm_linux");
            println!("cargo:rustc-link-lib=stdc++");
        }
        ("x86_64", "macos") => {
            println!("cargo:rustc-link-search=native=./executors");
            println!("cargo:rustc-link-lib=static=bls384_256_amd_macos");
            println!("cargo:rustc-link-lib=c++");
        }
        ("aarch64", "macos") | ("arm", "macos") => {
            println!("cargo:rustc-link-search=native=./executors");
            println!("cargo:rustc-link-lib=static=bls384_256_arm_macos");
            println!("cargo:rustc-link-lib=c++");
        }
        ("x86_64", "windows") => {
            let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
            if env == "msvc" {
                panic!(
                    "The x86_64-pc-windows-msvc target is not supported: only a MinGW/GNU-compatible \
                     static archive is provided. Use the x86_64-pc-windows-gnu target instead, or \
                     supply an MSVC-compatible import/static library."
                );
            }
            println!("cargo:rustc-link-search=native=./executors");
            println!("cargo:rustc-link-lib=static=bls384_256_amd_windows");
            println!("cargo:rustc-link-lib=advapi32");
            println!("cargo:rustc-link-lib=stdc++");
        }
        _ => panic!("Unsupported target: {os}-{target}"),
    }
}
