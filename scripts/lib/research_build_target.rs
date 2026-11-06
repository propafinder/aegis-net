/// Structural safety for a Cargo target embedded in a build directive.
/// Release admission still uses the manifest's exact supported-target list.
pub(crate) fn safe_cargo_target(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::safe_cargo_target;

    #[test]
    fn supported_cargo_targets_preserve_underscores() {
        for target in [
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "x86_64-pc-windows-msvc",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
        ] {
            assert!(safe_cargo_target(target), "{target}");
        }
        assert!(safe_cargo_target(&"a".repeat(128)));
    }

    #[test]
    fn unsafe_or_empty_directive_values_are_refused() {
        for target in [
            "",
            "x86_64\ncargo:rustc-env=INJECTED=yes",
            "x86_64\rcargo:rustc-env=INJECTED=yes",
            "x86_64\tlinux",
            "../target.json",
            "\"x86_64\"",
            "аarch64-unknown-linux-gnu",
        ] {
            assert!(!safe_cargo_target(target), "{target:?}");
        }
        assert!(!safe_cargo_target(&"a".repeat(129)));
    }
}
