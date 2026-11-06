#![cfg(feature = "lua")]

use aegis_core::lua_engine::try_apply_chunk_hook;
use std::io::Write;

#[test]
fn lua_mutate_chunk() {
    let mut f = tempfile::NamedTempFile::new().expect("temp");
    writeln!(
        f,
        r#"
function mutate_chunk(data, ip_ver)
  return data .. ""
end
"#
    )
    .unwrap();
    let buf = b"hello";
    let r = try_apply_chunk_hook(Some(f.path()), buf, 4).expect("ok");
    assert_eq!(r.as_deref(), Some(&b"hello"[..]));
}
