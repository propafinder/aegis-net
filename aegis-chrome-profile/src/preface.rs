//! HTTP/2 connection preface bytes implied by the profile.
//!
//! `build.rs` includes this file so a profile edit that forgets the checked-in
//! fixture fails the build, not only the unit test.

pub fn connection_preface(settings: &[(u16, u32)], window_increment: u32) -> Vec<u8> {
    let mut out = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    let mut payload = Vec::with_capacity(settings.len() * 6);
    for (id, value) in settings {
        payload.extend_from_slice(&id.to_be_bytes());
        payload.extend_from_slice(&value.to_be_bytes());
    }
    push_frame(&mut out, 0x4, &payload);
    if window_increment > 0 {
        push_frame(&mut out, 0x8, &window_increment.to_be_bytes());
    }
    out
}

fn push_frame(out: &mut Vec<u8>, kind: u8, payload: &[u8]) {
    let len = payload.len();
    out.push((len >> 16) as u8);
    out.push((len >> 8) as u8);
    out.push(len as u8);
    out.push(kind);
    out.push(0);
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(payload);
}
