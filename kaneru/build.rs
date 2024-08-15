#![feature(exit_status_error)]

use std::process::Command;
use std::path::Path;
// use std::fmt::format;

fn main() {
    std::env::set_var("REBUILD", format!("{:?}", std::time::Instant::now()));
    println!("cargo:rerun-if-env-changed=REBUILD");
    // println!("rerun-if-changed=../kaneru-ebpf");
    let profile = std::env::var("PROFILE").into_iter()
        .find(|p| p == "release")
        .unwrap_or("dev".to_string());
    Command::new("cargo")
        .args(["build", &format!("--profile={}", profile)])
        .current_dir(Path::new("../kaneru-ebpf"))
        .env_remove("RUSTUP_TOOLCHAIN") // many things that are set for this crate won't work when targeting eBPF
        .env_remove("RUSTC")
        .env_remove("CARGO_CFG_TARGET_FEATURE")
        .env_remove("RUSTC_LINKER")
        .env_remove("CARGO_BUILD_RUSTFLAGS")
        .env_remove(&format!("CARGO_PROFILE_{}_LTO", profile))
        .status()
        .expect("failed to run cargo to build ebpf")
        .exit_ok()
        .expect("failed to build ebpf");
}
