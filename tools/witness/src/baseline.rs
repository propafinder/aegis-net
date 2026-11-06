//! Browser-like structural baseline heuristics for the first witness slice.

/// Return true when ALPN contains common browser HTTPS protocol names.
pub fn has_browser_like_alpn(alpn: &[String]) -> bool {
    alpn.iter()
        .any(|value| matches!(value.as_str(), "h2" | "http/1.1" | "h3"))
}

/// Minimal hostname structure check for SNI scoring.
pub fn has_dns_like_sni(sni: Option<&str>) -> bool {
    let Some(sni) = sni else {
        return false;
    };
    if sni.len() > 253 || !sni.contains('.') {
        return false;
    }
    sni.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}
