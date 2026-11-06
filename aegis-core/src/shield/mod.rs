//! Aegis-Shield: sentinel, строки, Lua (feature).

pub mod sentinel;
pub mod string_crypt;

pub use sentinel::{init_sentinel, SentinelConfig};
pub use string_crypt::decrypt_env_blob;
