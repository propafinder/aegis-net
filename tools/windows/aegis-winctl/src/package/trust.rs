//! The same Ed25519 release publisher anchor as bootstrap-install.sh. A valid
//! manifest signature authenticates bytes; it is not Windows Authenticode.
use super::*;
use ring::signature::{UnparsedPublicKey, ED25519};

const PUBLISHER_KEY: [u8; 32] = [
    0xe9, 0x3d, 0x0f, 0x2b, 0x86, 0xa8, 0xeb, 0xce, 0x3b, 0xce, 0x69, 0xe2, 0x86, 0x43, 0xc0, 0x23,
    0x7b, 0x11, 0x22, 0xf8, 0x6e, 0x05, 0x37, 0xf0, 0xe0, 0x60, 0xd7, 0xd3, 0x8a, 0xd9, 0xe2, 0x6d,
];

#[derive(Args)]
#[group(required = true, multiple = false)]
pub(crate) struct TrustArgs {
    /// Developer kit: hash obtained independently through an authenticated channel.
    #[arg(long)]
    pub(crate) manifest_sha256: Option<String>,
    /// Detached 64-byte Ed25519 signature from the pinned AEGIS publisher.
    #[arg(long)]
    pub(crate) manifest_signature: Option<PathBuf>,
}
#[cfg(windows)]
impl TrustArgs {
    #[cfg(test)]
    pub(crate) fn pinned(hash: String) -> Self {
        Self {
            manifest_sha256: Some(hash),
            manifest_signature: None,
        }
    }
    pub(crate) fn resolve(&self, package: &Path) -> Result<(String, bool), WinctlError> {
        match (&self.manifest_sha256, &self.manifest_signature) {
            (Some(hash), None) => Ok((hash.clone(), false)),
            (None, Some(signature)) => Ok((verify_signature(package, signature)?, true)),
            _ => Err(invalid()),
        }
    }
}

fn verify_bytes(raw: &[u8], signature: &[u8], key: &[u8]) -> Result<(), WinctlError> {
    if signature.len() != 64 {
        return Err(invalid());
    }
    UnparsedPublicKey::new(&ED25519, key)
        .verify(raw, signature)
        .map_err(|_| invalid())
}
pub(super) fn verify_signature(package: &Path, signature: &Path) -> Result<String, WinctlError> {
    let raw = read_regular(&package.join("manifest.json"), 65536)?;
    verify_detached_bytes(&raw, signature)?;
    Ok(hash(&raw))
}

pub(super) fn verify_detached(path: &Path, signature: &Path) -> Result<Vec<u8>, WinctlError> {
    let raw = read_regular(path, 65536)?;
    verify_detached_bytes(&raw, signature)?;
    Ok(raw)
}

fn verify_detached_bytes(raw: &[u8], signature: &Path) -> Result<(), WinctlError> {
    let signature = read_regular(signature, 64)?;
    verify_bytes(raw, &signature, &PUBLISHER_KEY)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    #[test]
    fn signature_rejects_mutation_wrong_key_truncation_and_signature_substitution() {
        let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let signer = Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
        let raw = br#"{"schema":2,"platform":"windows-x86_64"}"#;
        let signed = signer.sign(raw);
        assert!(verify_bytes(raw, signed.as_ref(), signer.public_key().as_ref()).is_ok());
        assert!(verify_bytes(
            b"different manifest",
            signed.as_ref(),
            signer.public_key().as_ref()
        )
        .is_err());
        assert!(verify_bytes(raw, signed.as_ref(), &PUBLISHER_KEY).is_err());
        assert!(verify_bytes(raw, &signed.as_ref()[..63], signer.public_key().as_ref()).is_err());
        assert!(verify_bytes(
            raw,
            signer.sign(b"other").as_ref(),
            signer.public_key().as_ref()
        )
        .is_err());
    }
}
