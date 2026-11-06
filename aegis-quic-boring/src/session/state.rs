//! Handshake state shared between the BoringSSL callbacks and the quinn
//! `Session` impl.
//!
//! BoringSSL pushes into this struct (handshake bytes, traffic secrets, alerts)
//! from the `SSL_QUIC_METHOD` callbacks; quinn pulls out of it via
//! `write_handshake`/`next_1rtt_keys`. It holds no BoringSSL types, so its
//! level/keys bookkeeping is unit-testable on its own.

use quinn_proto::crypto::{KeyPair, Keys};
use zeroize::Zeroizing;

use crate::crypto::keys::{keys_from_secret, packet_key_from_secret};
use crate::crypto::secrets::next_secret;
use crate::crypto::suite::Suite;
use crate::level::{Level, LEVELS};

#[derive(Default)]
pub struct SessionState {
    /// Negotiated TLS 1.3 suite, once BoringSSL reports one.
    pub suite: Option<Suite>,
    /// Traffic secrets, indexed by [`Level`].
    read_secrets: [Option<Zeroizing<Vec<u8>>>; LEVELS],
    write_secrets: [Option<Zeroizing<Vec<u8>>>; LEVELS],
    /// Outgoing handshake bytes, indexed by [`Level`].
    write_bufs: [Vec<u8>; LEVELS],
    /// Fatal alert requested by BoringSSL, if any.
    pub alert: Option<u8>,
    /// Highest level whose `Keys` were already handed to quinn.
    emitted: Level,
    /// 1-RTT secrets tracked across key updates (RFC 9001 §6).
    app_write_secret: Option<Zeroizing<Vec<u8>>>,
    app_read_secret: Option<Zeroizing<Vec<u8>>>,
}

impl SessionState {
    pub fn new() -> Self {
        Self {
            emitted: Level::Initial,
            ..Default::default()
        }
    }

    // --- pushed in by the BoringSSL callbacks ------------------------------

    pub fn set_read_secret(&mut self, level: Level, suite: Suite, secret: &[u8]) {
        self.suite = Some(suite);
        self.read_secrets[level.index()] = Some(Zeroizing::new(secret.to_vec()));
        if level == Level::Application {
            self.app_read_secret = Some(Zeroizing::new(secret.to_vec()));
        }
    }

    pub fn set_write_secret(&mut self, level: Level, suite: Suite, secret: &[u8]) {
        self.suite = Some(suite);
        self.write_secrets[level.index()] = Some(Zeroizing::new(secret.to_vec()));
        if level == Level::Application {
            self.app_write_secret = Some(Zeroizing::new(secret.to_vec()));
        }
    }

    pub fn add_handshake_data(&mut self, level: Level, data: &[u8]) {
        self.write_bufs[level.index()].extend_from_slice(data);
    }

    pub fn set_alert(&mut self, alert: u8) {
        self.alert = Some(alert);
    }

    // --- pulled out by the quinn Session impl ------------------------------

    /// True if any level still has handshake bytes queued.
    pub fn has_pending_data(&self) -> bool {
        self.write_bufs.iter().any(|b| !b.is_empty())
    }

    /// Drain queued handshake bytes at or below `level` into `buf`.
    ///
    /// quinn asks for the data belonging to the keys it currently holds, so we
    /// emit everything up to and including the level whose keys were last
    /// returned.
    pub fn take_handshake_data(&mut self, buf: &mut Vec<u8>) {
        for i in 0..=self.emitted.index() {
            if !self.write_bufs[i].is_empty() {
                buf.append(&mut self.write_bufs[i]);
            }
        }
        // 0-RTT never carries CRYPTO frames; drop anything queued there.
        self.write_bufs[Level::EarlyData.index()].clear();
    }

    /// If the next handshake level has both directions' secrets available,
    /// build its `Keys`, mark it emitted, and return it.
    pub fn take_next_keys(&mut self) -> Option<Keys> {
        let suite = self.suite?;
        let next = self.emitted.next_handshake_level()?;
        let i = next.index();
        let read = self.read_secrets[i].as_ref()?;
        let write = self.write_secrets[i].as_ref()?;

        let (local_packet, local_header) = keys_from_secret(suite, write);
        let (remote_packet, remote_header) = keys_from_secret(suite, read);
        // Quinn owns the derived keys now. Retain only the current application
        // traffic secrets needed for a subsequent key update, not old levels.
        self.read_secrets[i] = None;
        self.write_secrets[i] = None;
        self.emitted = next;

        Some(Keys {
            header: KeyPair {
                local: Box::new(local_header),
                remote: Box::new(remote_header),
            },
            packet: KeyPair {
                local: Box::new(local_packet),
                remote: Box::new(remote_packet),
            },
        })
    }

    /// 0-RTT keys, if BoringSSL installed an early-data write secret.
    pub fn early_keys(
        &self,
    ) -> Option<(
        Box<dyn quinn_proto::crypto::HeaderKey>,
        Box<dyn quinn_proto::crypto::PacketKey>,
    )> {
        let suite = self.suite?;
        let secret = self.write_secrets[Level::EarlyData.index()].as_ref()?;
        let (packet, header) = keys_from_secret(suite, secret);
        Some((Box::new(header), Box::new(packet)))
    }

    /// Advance the 1-RTT secrets one key-update generation (RFC 9001 §6) and
    /// return the resulting packet keys.
    pub fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn quinn_proto::crypto::PacketKey>>> {
        let suite = self.suite?;
        let write = next_secret(suite, self.app_write_secret.as_ref()?);
        let read = next_secret(suite, self.app_read_secret.as_ref()?);
        let pair = KeyPair {
            local: Box::new(packet_key_from_secret(suite, &write))
                as Box<dyn quinn_proto::crypto::PacketKey>,
            remote: Box::new(packet_key_from_secret(suite, &read))
                as Box<dyn quinn_proto::crypto::PacketKey>,
        };
        self.app_write_secret = Some(write);
        self.app_read_secret = Some(read);
        Some(pair)
    }

    /// The highest level whose keys quinn already holds.
    pub fn emitted_level(&self) -> Level {
        self.emitted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    #[test]
    fn keys_appear_only_when_both_directions_are_set() {
        let mut st = SessionState::new();
        st.set_write_secret(Level::Handshake, Suite::Aes128Gcm, &secret(1));
        assert!(
            st.take_next_keys().is_none(),
            "write-only must not emit keys"
        );
        st.set_read_secret(Level::Handshake, Suite::Aes128Gcm, &secret(2));
        assert!(st.take_next_keys().is_some());
        assert_eq!(st.emitted_level(), Level::Handshake);
    }

    #[test]
    fn key_progression_is_handshake_then_one_rtt() {
        let mut st = SessionState::new();
        // 1-RTT secrets set first must NOT jump the queue.
        st.set_write_secret(Level::Application, Suite::Aes128Gcm, &secret(3));
        st.set_read_secret(Level::Application, Suite::Aes128Gcm, &secret(4));
        assert!(st.take_next_keys().is_none(), "must not skip Handshake");

        st.set_write_secret(Level::Handshake, Suite::Aes128Gcm, &secret(1));
        st.set_read_secret(Level::Handshake, Suite::Aes128Gcm, &secret(2));
        assert!(st.take_next_keys().is_some());
        assert!(st.read_secrets[Level::Handshake.index()].is_none());
        assert!(st.write_secrets[Level::Handshake.index()].is_none());
        assert!(st.take_next_keys().is_some(), "1-RTT follows");
        assert!(st.read_secrets[Level::Application.index()].is_none());
        assert!(st.write_secrets[Level::Application.index()].is_none());
        // Only the ratchet's current generation remains for QUIC key updates.
        assert!(st.app_read_secret.is_some());
        assert!(st.app_write_secret.is_some());
        assert_eq!(st.emitted_level(), Level::Application);
        assert!(st.take_next_keys().is_none(), "no level past 1-RTT");
    }

    #[test]
    fn handshake_data_drains_up_to_emitted_level() {
        let mut st = SessionState::new();
        st.add_handshake_data(Level::Initial, b"client-hello");
        st.add_handshake_data(Level::Handshake, b"finished");

        let mut buf = Vec::new();
        st.take_handshake_data(&mut buf);
        assert_eq!(buf, b"client-hello", "handshake-level data is not yet due");
        assert!(st.has_pending_data());

        // once Handshake keys are emitted, its data becomes available
        st.set_write_secret(Level::Handshake, Suite::Aes128Gcm, &secret(1));
        st.set_read_secret(Level::Handshake, Suite::Aes128Gcm, &secret(2));
        st.take_next_keys().unwrap();
        let mut buf = Vec::new();
        st.take_handshake_data(&mut buf);
        assert_eq!(buf, b"finished");
        assert!(!st.has_pending_data());
    }

    #[test]
    fn key_update_ratchets_both_directions() {
        let mut st = SessionState::new();
        st.set_write_secret(Level::Application, Suite::Aes128Gcm, &secret(3));
        st.set_read_secret(Level::Application, Suite::Aes128Gcm, &secret(4));
        assert!(st.next_1rtt_keys().is_some());
        // secrets advanced, so a second update yields different material
        let before = st.app_write_secret.clone().unwrap();
        assert!(st.next_1rtt_keys().is_some());
        assert_ne!(before, st.app_write_secret.clone().unwrap());
    }

    #[test]
    fn no_keys_without_a_negotiated_suite() {
        let mut st = SessionState::new();
        assert!(st.take_next_keys().is_none());
        assert!(st.next_1rtt_keys().is_none());
        assert!(st.early_keys().is_none());
    }
}
