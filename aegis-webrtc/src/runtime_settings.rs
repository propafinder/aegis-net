//! Private native configuration. Credential readers must enforce platform custody.
use crate::{CarrierConfig, Error, IcePolicy, Result, TurnServer};
use serde::Deserialize;
use std::{
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSettings {
    pub bind: SocketAddr,
    pub connect_timeout_ms: u64,
    pub stall_timeout_ms: u64,
    pub max_lifetime_ms: u64,
    pub ice: PolicySettings,
}

#[derive(Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicySettings {
    Loopback,
    DirectIntermediary {
        allowed_peer_ips: Vec<IpAddr>,
    },
    RelayOnly {
        allowed_relay_ips: Vec<IpAddr>,
        turn: Vec<TurnSettings>,
    },
    SfuMedia,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnSettings {
    pub endpoint: SocketAddr,
    pub username_file: PathBuf,
    pub password_file: PathBuf,
}

impl RuntimeSettings {
    pub fn load_with(
        &self,
        mut private_read: impl FnMut(&Path, usize) -> std::io::Result<Zeroizing<Vec<u8>>>,
    ) -> Result<CarrierConfig> {
        if !(1..=30_000).contains(&self.connect_timeout_ms)
            || !(1..=30_000).contains(&self.stall_timeout_ms)
            || !(1..=3_600_000).contains(&self.max_lifetime_ms)
        {
            return Err(Error::Configuration);
        }
        let ice = match &self.ice {
            PolicySettings::Loopback => IcePolicy::Loopback,
            PolicySettings::DirectIntermediary { allowed_peer_ips } => {
                IcePolicy::DirectIntermediary {
                    allowed_peer_ips: allowed_peer_ips.clone(),
                }
            }
            PolicySettings::RelayOnly {
                allowed_relay_ips,
                turn,
            } => {
                if turn.is_empty() || turn.len() > 4 {
                    return Err(Error::Configuration);
                }
                let mut servers = Vec::new();
                for settings in turn {
                    if !settings.username_file.is_absolute()
                        || !settings.password_file.is_absolute()
                        || settings.username_file == settings.password_file
                    {
                        return Err(Error::Configuration);
                    }
                    let user = private_read(&settings.username_file, 257)
                        .map_err(|_| Error::Configuration)?;
                    let password = private_read(&settings.password_file, 257)
                        .map_err(|_| Error::Configuration)?;
                    let text = |raw: &[u8]| -> Result<String> {
                        let value = std::str::from_utf8(raw).map_err(|_| Error::Configuration)?;
                        Ok(value.strip_suffix('\n').unwrap_or(value).to_owned())
                    };
                    servers.push(TurnServer::udp(
                        settings.endpoint,
                        text(&user)?,
                        text(&password)?,
                    )?);
                }
                IcePolicy::RelayOnly {
                    servers,
                    allowed_relay_ips: allowed_relay_ips.clone(),
                }
            }
            PolicySettings::SfuMedia => return Err(Error::UnsupportedSfu),
        };
        ice.validate(self.bind)?;
        Ok(CarrierConfig {
            bind: self.bind,
            ice,
            connect_timeout: Duration::from_millis(self.connect_timeout_ms),
            stall_timeout: Duration::from_millis(self.stall_timeout_ms),
            max_lifetime: Duration::from_millis(self.max_lifetime_ms),
        })
    }
}
