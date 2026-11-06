//! Runtime anti-debug / VM (лёгкие эвристики; не криптостойкость).

use tracing::warn;

#[derive(Debug, Clone, Default)]
pub struct SentinelConfig {
    pub sleep_if_vm: bool,
    pub exit_if_debugger: bool,
}

fn shield_bypass_requested() -> bool {
    std::env::var("AEGIS_SHIELD").ok().as_deref() == Some("0")
}

/// Проверки при старте агента. Release builds игнорируют `AEGIS_SHIELD=0`.
pub fn init_sentinel(cfg: &SentinelConfig) {
    if shield_bypass_requested() {
        if cfg!(debug_assertions) {
            return;
        }
        warn!("ignoring AEGIS_SHIELD=0 outside debug builds");
    }
    if tracer_pid_linux().unwrap_or(0) != 0 {
        warn!("TracerPid != 0 — возможен отладчик");
        if cfg.exit_if_debugger {
            std::process::exit(1);
        }
    }
    if likely_vm_linux() && cfg.sleep_if_vm {
        warn!("Похоже на VM — «спящий» режим урезан (только предупреждение)");
    }
    #[cfg(windows)]
    if is_debugger_windows() {
        warn!("IsDebuggerPresent");
        if cfg.exit_if_debugger {
            std::process::exit(1);
        }
    }
}

fn tracer_pid_linux() -> Option<u32> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in s.lines() {
        if line.starts_with("TracerPid:") {
            return line.split_whitespace().nth(1)?.parse().ok();
        }
    }
    None
}

fn likely_vm_linux() -> bool {
    if let Ok(cpu) = std::fs::read_to_string("/proc/cpuinfo") {
        let l = cpu.to_lowercase();
        if l.contains("hypervisor") || l.contains("kvm") || l.contains("vmware") {
            return true;
        }
    }
    false
}

#[cfg(windows)]
fn is_debugger_windows() -> bool {
    #[link(name = "kernel32")]
    extern "system" {
        fn IsDebuggerPresent() -> i32;
    }
    unsafe { IsDebuggerPresent() != 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shield_bypass_flag_is_parseable() {
        unsafe {
            std::env::set_var("AEGIS_SHIELD", "0");
        }
        assert!(shield_bypass_requested());
        unsafe {
            std::env::remove_var("AEGIS_SHIELD");
        }
    }
}
