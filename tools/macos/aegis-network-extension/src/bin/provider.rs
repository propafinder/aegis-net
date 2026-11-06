#[cfg(target_os = "macos")]
fn main() {
    aegis_network_extension::apple::provider_main();
}
#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("macOS NetworkExtension requires macOS");
    std::process::exit(2);
}
