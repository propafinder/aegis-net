//! Original host-path expansion helper. No custody or admission is granted.
pub fn expand_tilde(path: &std::path::Path) -> std::path::PathBuf {
    if let Some(s) = path.to_str() {
        if let Some(rest) = s.strip_prefix("~/") {
            if let Some(h) = dirs::home_dir() {
                return h.join(rest);
            }
        }
    }
    path.to_path_buf()
}
