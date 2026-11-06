//! Персистентность state (JSON) во временном файле.

use aegis_core::brain::StrategyKey;
use aegis_core::state::StateStore;
use std::collections::HashMap;

#[test]
fn state_roundtrip_file() {
    let dir = std::env::temp_dir().join(format!("aegis-state-{}", std::process::id()));
    let _ = std::fs::remove_file(&dir);
    let mut st = StateStore::load(&dir).expect("load");
    let hk = StrategyKey::for_dst(4).hash_key();
    st.data.insert(hk.clone(), {
        let mut m = HashMap::new();
        m.insert(
            "passthrough".into(),
            aegis_core::state::StrategyStats {
                success_rate: 0.5,
                avg_handshake_ms: 0.0,
                last_rst_source: Some("Remote".into()),
                confidence: 0.5,
            },
        );
        m
    });
    st.save().expect("save");
    let st2 = StateStore::load(&dir).expect("reload");
    assert!(st2.data.contains_key(&hk));
    let _ = std::fs::remove_file(&dir);
}
