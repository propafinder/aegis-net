//! Explicit paired operator, separate from relay Open/PolicyAck and full-wide.
use aegis_core::{
    carrier_runtime::PrivacySettings,
    secret_file,
    secure_channel::{
        private_control::{self, ControlInput, ControlProfile},
        Client, ClientSettings, Server, ServerSettings,
    },
    traffic_privacy::{cover_control::CoverModel, schedule_emission::ScheduleProfile},
};
use serde::Deserialize;
use std::{io, net::SocketAddr, path::Path, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    time::{timeout_at, Instant},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    endpoint: SocketAddr,
    deadline_ms: u64,
    tls: Role,
    profile: Profile,
    #[serde(default)]
    authenticated_shaping: Option<PrivacySettings>,
}
#[derive(Deserialize)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
enum Role {
    Client { settings: ClientSettings },
    Server { settings: ServerSettings },
}
#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
enum Profile {
    Cover {
        tokens: Vec<Vec<u8>>,
        weights: Vec<u64>,
        bits: u8,
        capacity: usize,
        io_timeout_ms: u64,
    },
    GeneralCover {
        tokens: Vec<Vec<u8>>,
        weights: Vec<u64>,
        capacity: usize,
        horizon: usize,
        io_timeout_ms: u64,
    },
    BinarySchedule {
        slots: usize,
        capacity: usize,
        cadence_ms: u64,
        io_timeout_ms: u64,
        truthful: u32,
        flipped: u32,
        #[serde(deserialize_with = "rational_integer")]
        limit_numerator: u128,
        #[serde(deserialize_with = "rational_integer")]
        limit_denominator: u128,
    },
}
// Tagged serde content cannot deserialize u128 directly. Canonical bounded
// decimal strings avoid numeric truncation or platform-dependent conversion.
fn rational_integer<'de, D: serde::Deserializer<'de>>(decoder: D) -> Result<u128, D::Error> {
    let text = String::deserialize(decoder)?;
    if text.is_empty()
        || text.len() > 39
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(serde::de::Error::custom(
            "invalid bounded public rational integer",
        ));
    }
    text.parse()
        .map_err(|_| serde::de::Error::custom("public rational integer overflow"))
}
impl Profile {
    fn build(self) -> io::Result<ControlProfile> {
        match self {
            Self::Cover {
                tokens,
                weights,
                bits,
                capacity,
                io_timeout_ms,
            } => Ok(ControlProfile::Cover(CoverModel::new(
                tokens,
                weights,
                bits,
                capacity,
                Duration::from_millis(io_timeout_ms),
            )?)),
            Self::GeneralCover {
                tokens,
                weights,
                capacity,
                horizon,
                io_timeout_ms,
            } => Ok(ControlProfile::Cover(CoverModel::new_general(
                tokens,
                weights,
                capacity,
                horizon,
                Duration::from_millis(io_timeout_ms),
            )?)),
            Self::BinarySchedule {
                slots,
                capacity,
                cadence_ms,
                io_timeout_ms,
                truthful,
                flipped,
                limit_numerator,
                limit_denominator,
            } => Ok(ControlProfile::BinarySchedule(ScheduleProfile::new(
                slots,
                capacity,
                Duration::from_millis(cadence_ms),
                Duration::from_millis(io_timeout_ms),
                truthful,
                flipped,
                limit_numerator,
                limit_denominator,
            )?)),
        }
    }
}
fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "private control operator refused",
    )
}

pub fn run(
    config_path: &Path,
    input: Option<&Path>,
    output: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = secret_file::read(config_path, 64 * 1024)?;
    // Do not expose config contents or file/key paths through parser diagnostics.
    let mut config: Config = serde_json::from_slice(&bytes).map_err(|_| refused())?;
    let deadline = Duration::from_millis(config.deadline_ms);
    if config.authenticated_shaping.is_some()
        || deadline.is_zero()
        || deadline > Duration::from_secs(60)
    {
        return Err(refused().into());
    }
    let base = config_path.parent().ok_or_else(refused)?;
    let profile = config.profile.build()?;
    profile.validate()?;
    let possible_releases = profile.possible_schedule_releases();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    match &mut config.tls {
        Role::Client { settings } => {
            if output.is_some() {
                return Err(refused().into());
            }
            let input = ControlInput::read_private(&profile, input.ok_or_else(refused)?)?;
            settings.resolve_paths(base);
            let client = Client::load(settings)?;
            let outcome = runtime.block_on(async {
                let end = Instant::now() + deadline;
                timeout_at(end, async {
                    let stream = TcpStream::connect(config.endpoint)
                        .await
                        .map_err(private_control::ControlFailure::from)?;
                    private_control::send_once_until(
                        &client,
                        &config.authenticated_shaping,
                        stream,
                        profile,
                        input,
                        end,
                    )
                    .await
                })
                .await
            });
            let receipt = match outcome {
                Ok(Ok(receipt)) => receipt,
                Ok(Err(failure)) => {
                    let spent = failure
                        .schedule
                        .as_ref()
                        .map(|s| &s.receipt.accounting)
                        .or_else(|| failure.completed_schedule.as_ref().map(|s| &s.accounting));
                    println!(
                        "{}",
                        serde_json::json!({"operation":"private_control", "status":"failed",
                        "schedule_accounting_unknown":failure.schedule_accounting_unknown,
                        "possible_releases_upper_bound":possible_releases, "actual_accounting":spent})
                    );
                    return Err(failure.into());
                }
                Err(_) => {
                    println!(
                        "{}",
                        serde_json::json!({"operation":"private_control", "status":"deadline",
                        "schedule_accounting_unknown":possible_releases.is_some(),
                        "possible_releases_upper_bound":possible_releases})
                    );
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "private control operator deadline",
                    )
                    .into());
                }
            };
            println!(
                "{}",
                serde_json::json!({"operation":"private_control", "peer_decoded":true,
                "actual_accounting": receipt.schedule.as_ref().map(|s| &s.accounting), "installed_full_wide":false})
            );
        }
        Role::Server { settings } => {
            if input.is_some() {
                return Err(refused().into());
            }
            let output = output.ok_or_else(refused)?;
            secret_file::trusted_parent(output)?;
            if output.symlink_metadata().is_ok() {
                return Err(refused().into());
            }
            settings.resolve_paths(base);
            let server = Server::load(settings)?;
            let received = runtime
                .block_on(async {
                    let _watcher = server.start_registry_watcher();
                    let end = Instant::now() + deadline;
                    timeout_at(end, async {
                        let listener = TcpListener::bind(config.endpoint).await?;
                        println!("{{\"operation\":\"private_control\",\"state\":\"listening\"}}");
                        std::io::Write::flush(&mut std::io::stdout())?;
                        let (stream, _) = listener.accept().await?;
                        private_control::receive_once_until(
                            &server,
                            &config.authenticated_shaping,
                            stream,
                            profile,
                            end,
                        )
                        .await
                        .map_err(|e| io::Error::new(e.kind, "private control exchange failed"))
                    })
                    .await
                })
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "private control operator deadline")
                })??;
            let cells = received.cells();
            received.save_private_new(output)?;
            println!("{{\"operation\":\"private_control\",\"decoded_file_written\":true,\"cells\":{cells},\"installed_full_wide\":false}}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_u128_public_budget_and_noncanonical_refusals() {
        let profile = |n: &str| {
            format!(
                r#"{{"mode":"binary_schedule","slots":1,"capacity":1,"cadence_ms":1,"io_timeout_ms":10,"truthful":1,"flipped":1,"limit_numerator":"{n}","limit_denominator":"1"}}"#
            )
        };
        assert!(
            serde_json::from_str::<Profile>(&profile(&u128::MAX.to_string()))
                .unwrap()
                .build()
                .is_ok()
        );
        for bad in ["01", "-1", "340282366920938463463374607431768211456", ""] {
            assert!(serde_json::from_str::<Profile>(&profile(bad)).is_err());
        }
    }
}
