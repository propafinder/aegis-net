//! Load an existing install-local RFC 1929 credential. This never provisions
//! a record or derives local credentials from enrollment/device material.
use serde::{Deserialize, Deserializer};
use std::{fmt, io, path::Path};
use zeroize::Zeroizing;

pub const MAX_RECORD_BYTES: u64 = 1024;

#[derive(Clone)]
pub struct LocalSocksAuth {
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}

impl fmt::Debug for LocalSocksAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalSocksAuth([redacted])")
    }
}

fn rejected(kind: io::ErrorKind) -> io::Error {
    io::Error::new(kind, "local SOCKS credential rejected")
}

fn private_text<'de, D: Deserializer<'de>>(de: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(de).map(Zeroizing::new)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    #[serde(deserialize_with = "private_text")]
    username: Zeroizing<String>,
    #[serde(deserialize_with = "private_text")]
    password: Zeroizing<String>,
}

impl LocalSocksAuth {
    /// Require an existing absolute, bounded, descriptor-checked private file.
    /// Unix uses the existing owner/root and no-follow secret policy; Windows
    /// uses its existing owner/SYSTEM/Administrators descriptor ACL policy.
    pub fn load(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(rejected(io::ErrorKind::InvalidInput));
        }
        crate::secret_file::trusted_read_parent(path).map_err(|error| rejected(error.kind()))?;
        let raw = crate::secret_file::read(path, MAX_RECORD_BYTES)
            .map_err(|error| rejected(error.kind()))?;
        Self::from_bytes(&raw)
    }

    fn from_bytes(raw: &[u8]) -> io::Result<Self> {
        if raw.len() as u64 > MAX_RECORD_BYTES {
            return Err(rejected(io::ErrorKind::InvalidData));
        }
        let record: Record =
            serde_json::from_slice(raw).map_err(|_| rejected(io::ErrorKind::InvalidData))?;
        if record.version != 1
            || !(1..=255).contains(&record.username.len())
            || !(1..=255).contains(&record.password.len())
        {
            return Err(rejected(io::ErrorKind::InvalidData));
        }
        Ok(Self {
            username: record.username,
            password: record.password,
        })
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        &self.password
    }
}

#[cfg(test)]
#[path = "local_socks_auth_tests.rs"]
mod tests;
