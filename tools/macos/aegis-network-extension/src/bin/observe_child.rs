//! Staged signed role probe only. No helper protocol, Store or Ready emission.
#[cfg(target_os = "macos")]
fn main() {
    if std::env::args_os().len() != 1 {
        std::process::exit(2);
    }
    if aegis_network_extension::app_group::CapturedAppGroupInputs::observation_child_staging_preflight()
        .is_err()
    {
        std::process::exit(2);
    }
    // Even with a valid future signature/entitlement, there is no product
    // helper, child protocol or Store owner. Never signal Ready here.
    std::process::exit(2);
}

#[cfg(not(target_os = "macos"))]
fn main() {
    std::process::exit(2);
}
