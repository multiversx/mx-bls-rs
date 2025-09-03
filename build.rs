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
        (_, "windows") => {
            println!("cargo:rustc-link-search=native=./executors");
            println!("cargo:rustc-link-lib=static=bls384_256_arm_macos");
            println!("cargo:rustc-link-lib=stdc++");
        }
        _ => panic!("Unsupported target: {os}-{target}"),
    }
}
