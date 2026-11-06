//! Format validation for the 256-bit tokens emitted by Aegis provisioning.
//! No validator can prove entropy of an operator-supplied string: production
//! tokens must be generated from an OS CSPRNG, never composed as passwords.
use zeroize::Zeroizing;

pub fn validate(value: &str) -> Result<(), &'static str> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("auth_token_requires_32_random_bytes_encoded_as_64_hex_characters");
    }
    let bytes = Zeroizing::new(hex::decode(value).map_err(|_| "auth_token_invalid_hex")?);
    if bytes.iter().all(|byte| *byte == bytes[0]) {
        return Err("auth_token_repeated_byte_placeholder_rejected");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn rejects_passwords_and_placeholders_but_accepts_generator_output() {
        for token in [
            "change-me".to_owned(),
            "a".repeat(64),
            "ab".repeat(32),
            "g".repeat(64),
        ] {
            assert!(super::validate(&token).is_err());
        }
        use rand::RngCore;
        let mut key = zeroize::Zeroizing::new([0; 32]);
        rand::rngs::OsRng.fill_bytes(&mut *key);
        assert!(super::validate(&hex::encode(*key)).is_ok());
    }
}
