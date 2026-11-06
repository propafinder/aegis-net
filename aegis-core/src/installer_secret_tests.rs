use super::*;

#[test]
fn url_lf_utf8_and_exact_byte_boundary() {
    assert_eq!(
        &*checked_text("https://example.test/é\n".as_bytes(), URL_LIMIT, true).unwrap(),
        "https://example.test/é"
    );
    assert!(checked_text(b"https://example.test/\n\n", URL_LIMIT, true).is_err());
    assert!(checked_text(b"https://example.test/\r\n", URL_LIMIT, true).is_err());
    assert!(checked_text(b"https://example.test/\0", URL_LIMIT, true).is_err());
    assert!(checked_text(&vec![b'x'; URL_LIMIT], URL_LIMIT, true).is_ok());
    assert!(checked_text(&vec![b'x'; URL_LIMIT + 1], URL_LIMIT, true).is_err());
    assert!(checked_text(&[0xff], URL_LIMIT, true).is_err());
}

#[test]
fn token_stdin_is_bounded_and_does_not_trim() {
    let value = token_from_stdin(b"ordinary token with spaces".as_slice()).unwrap();
    assert_eq!(&*value, "ordinary token with spaces");
    for bytes in [b"".as_slice(), b"token\n", b"token\t", b"token\0"] {
        assert!(token_from_stdin(bytes).is_err());
    }
    assert!(token_from_stdin(vec![b'x'; TOKEN_LIMIT].as_slice()).is_ok());
    assert!(token_from_stdin(vec![b'x'; TOKEN_LIMIT + 1].as_slice()).is_err());
}

#[cfg(unix)]
#[test]
fn actual_reader_refuses_links_public_modes_and_writable_ancestry() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("access-url.txt");
    let bytes = b"https://fixture.invalid/bundle?token=owned-synthetic-sentinel\n";
    crate::secret_file::write_private_new(&file, bytes).unwrap();
    assert_eq!(
        &*read_url(&file).unwrap(),
        "https://fixture.invalid/bundle?token=owned-synthetic-sentinel"
    );
    let linked = dir.path().join("linked");
    symlink(&file, &linked).unwrap();
    assert!(read_url(&linked).is_err());
    let hard = dir.path().join("hard");
    std::fs::hard_link(&file, &hard).unwrap();
    assert!(read_url(&file).is_err());
    std::fs::remove_file(hard).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_url(&file).is_err());
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(read_url(dir.path()).is_err());
    assert!(read_url(Path::new("relative-url")).is_err());
    assert!(read_url(&dir.path().join("missing")).is_err());
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o722)).unwrap();
    assert!(read_url(&file).is_err());
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(std::fs::read(&file).unwrap(), bytes);
}

#[test]
fn exclusive_output_preserves_unrelated_file_and_original_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("access-url.txt");
    let sentinel = dir.path().join("unrelated");
    crate::secret_file::write_private_new(&sentinel, b"preserve").unwrap();
    write_url(&file, "https://fixture.invalid/first").unwrap();
    let before = std::fs::metadata(&file).unwrap();
    assert!(write_url(&file, "https://fixture.invalid/second").is_err());
    assert_eq!(
        std::fs::read(&file).unwrap(),
        b"https://fixture.invalid/first"
    );
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"preserve");
    assert_eq!(
        std::fs::metadata(&file).unwrap().modified().unwrap(),
        before.modified().unwrap()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
