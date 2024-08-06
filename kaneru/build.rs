#![feature(exit_status_error)]

use std::process::Command;
use std::path::Path;
// use std::fmt::format;

fn main() {
    std::env::set_var("REBUILD", format!("{:?}", std::time::Instant::now()));
    println!("cargo:rerun-if-env-changed=REBUILD");
    // println!("rerun-if-changed=../kaneru-ebpf");
    let profile = std::env::var("PROFILE").into_iter()
        .filter(|p| p == "release").next()
        .unwrap_or("dev".to_string());
    Command::new("cargo")
        .args(&["build", &format!("--profile={}", profile)])
        .current_dir(&Path::new("../kaneru-ebpf"))
        .env_remove("RUSTUP_TOOLCHAIN") // a fairly ugly hack
        .env_remove("RUSTC")
        .status()
        .expect("failed to run cargo to build ebpf")
        .exit_ok()
        .expect("failed to build ebpf");
}
