#![cfg(feature = "lua")]

use aegis_core::lua_engine::try_apply_order_hook;
use std::io::Write;

#[test]
fn lua_order_rewrites_list() {
    let mut f = tempfile::NamedTempFile::new().expect("temp");
    writeln!(
        f,
        r#"
function order(pref, ip_ver)
  return {{ "passthrough", "multisplit" }}
end
"#
    )
    .unwrap();
    let preferred = vec!["multisplit".into(), "passthrough".into()];
    let r = try_apply_order_hook(Some(f.path()), &preferred, 4).expect("ok");
    assert_eq!(
        r,
        Some(vec!["passthrough".to_string(), "multisplit".to_string()])
    );
}
