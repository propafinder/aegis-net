//! Offline entry point. Network fixtures live in bounded, opt-in tests.
#[cfg(test)]
#[path = "../../../scripts/lib/research_build_target.rs"]
mod research_build_target_contract;

mod research_build_info;

/// Research inputs are bounded before parsing; these commands create no socket,
/// discover no fleet relationships and never turn model output into acceptance.
fn bounded_model_input<T: serde::de::DeserializeOwned>(
    path: &std::ffi::OsStr,
) -> Result<T, Box<dyn std::error::Error>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(1_048_577)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1_048_576 {
        return Err("research model input exceeds 1 MiB".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args == ["--build-info"] {
        return research_build_info::emit(
            "aegis-transport-lab",
            research_build_info::LAB_CAPABILITIES,
        );
    }
    if args.is_empty() || args == ["--help"] || args == ["-h"] {
        println!("aegis-transport-lab dependencies <private-inventory.json>\naegis-transport-lab topology <model.json>\naegis-transport-lab awgn <model.json>\naegis-transport-lab poisson-channel <model.json>\naegis-transport-lab privacy-channel <model.json>\naegis-transport-lab bittraps-channel <model.json>\nOffline models only; model results do not establish target-network protection.");
        return Ok(());
    }
    if args.len() == 2 && args[0] == "topology" {
        let report =
            aegis_transport_lab::research_topology::analyze(bounded_model_input(&args[1])?)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if args.len() == 2 && args[0] == "privacy-channel" {
        let report =
            aegis_transport_lab::research_channel::analyze(bounded_model_input(&args[1])?)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if args.len() == 2 && args[0] == "bittraps-channel" {
        let report = aegis_transport_lab::research_stream::analyze(bounded_model_input(&args[1])?)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if args.len() == 2 && args[0] == "awgn" {
        let report = aegis_transport_lab::research_covert_channels::run_awgn(bounded_model_input(
            &args[1],
        )?)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if args.len() == 2 && args[0] == "poisson-channel" {
        let report = aegis_transport_lab::research_covert_channels::run_poisson(
            bounded_model_input(&args[1])?,
        )?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if args.len() == 2 && args[0] == "dependencies" {
        let report = aegis_transport_lab::fleet_inventory::analyze_private_file(
            std::path::Path::new(&args[1]),
        )?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    Err("expected a documented offline command; use --help".into())
}
