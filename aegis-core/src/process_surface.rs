pub fn apply_process_alias(alias: &str) -> std::io::Result<()> {
    let sanitized = alias.trim();
    if sanitized.is_empty() {
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;

        let truncated = truncate_alias(sanitized, 15);
        let c_alias = CString::new(truncated)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "process_alias"))?;
        let rc = unsafe {
            libc::prctl(
                libc::PR_SET_NAME,
                c_alias.as_ptr() as libc::c_ulong,
                0,
                0,
                0,
            )
        };
        if rc != 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;

        let truncated = truncate_alias(sanitized, 63);
        let c_alias = CString::new(truncated)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "process_alias"))?;
        let rc = unsafe { libc::pthread_setname_np(c_alias.as_ptr()) };
        if rc != 0 {
            Err(std::io::Error::from_raw_os_error(rc))
        } else {
            Ok(())
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = sanitized;
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn truncate_alias(alias: &str, max_len: usize) -> String {
    alias.chars().take(max_len).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_alias_respects_bound() {
        assert_eq!(truncate_alias("abcdefghijklmnop", 8), "abcdefgh");
    }
}
