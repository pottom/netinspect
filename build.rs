//! Record the target triple, so a release can name the archive it needs.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_owned());
    println!("cargo:rustc-env=NETINSPECT_TARGET={target}");
    println!("cargo:rerun-if-changed=build.rs");
}
