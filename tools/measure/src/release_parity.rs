use serde_json::{json, Value};

pub struct ReleaseLatestParityInputs<'a> {
    pub server_result_json: &'a str,
    pub client_result_json: &'a str,
    pub negative_result_json: &'a str,
}

pub fn release_latest_parity(
    server: &Value,
    client: &Value,
    negative: &Value,
    inputs: ReleaseLatestParityInputs<'_>,
) -> Value {
    let server_pass = server["verdict"].as_str() == Some("PASS")
        && server["claims"]["latest_url_used"].as_bool() == Some(true)
        && server["claims"]["one_command_server_install"].as_bool() == Some(true)
        && server["claims"]["installed_git_sha_matches"].as_bool() == Some(true)
        && server["claims"]["service_active"].as_bool() == Some(true)
        && server["claims"]["bundle_issue_works"].as_bool() == Some(true)
        && server["claims"]["target_side_build_not_required"].as_bool() == Some(true);
    let client_pass = client["verdict"].as_str() == Some("PASS")
        && client["claims"]["latest_url_used"].as_bool() == Some(true)
        && client["claims"]["client_bundle_install"].as_bool() == Some(true)
        && client["claims"]["installed_git_sha_matches"].as_bool() == Some(true)
        && client["claims"]["service_active"].as_bool() == Some(true)
        && client["claims"]["socks_listener_active"].as_bool() == Some(true)
        && client["claims"]["installer_did_not_invoke_cargo_or_rustup"].as_bool() == Some(true);
    let negative_pass = negative["verdict"].as_str() == Some("PASS")
        && negative["claims"]["latest_url_used"].as_bool() == Some(true)
        && negative["claims"]["bad_checksum_rejected"].as_bool() == Some(true)
        && negative["claims"]["unsupported_arch_rejected"].as_bool() == Some(true)
        && negative["claims"]["wrong_expected_git_sha_detected"].as_bool() == Some(true);

    let server_latest_tag = latest_tag(server);
    let client_latest_tag = latest_tag(client);
    let negative_latest_tag = latest_tag(negative);
    let server_git_sha = server["expected_git_sha"].as_str().unwrap_or_default();
    let client_git_sha = client["expected_git_sha"].as_str().unwrap_or_default();
    let negative_git_sha = negative["expected_git_sha"].as_str().unwrap_or_default();
    let latest_tag_parity = !server_latest_tag.is_empty()
        && server_latest_tag == client_latest_tag
        && server_latest_tag == negative_latest_tag;
    let git_sha_parity = !server_git_sha.is_empty()
        && server_git_sha == client_git_sha
        && server_git_sha == negative_git_sha;
    let stable_channel = server["claims"]["source_release_channel"].as_str() == Some("stable")
        && client["claims"]["source_release_channel"].as_str() == Some("stable");

    let pass = server_pass
        && client_pass
        && negative_pass
        && latest_tag_parity
        && git_sha_parity
        && stable_channel;
    let status = if pass {
        "RELEASE_LATEST_PARITY_READY"
    } else {
        "RELEASE_LATEST_PARITY_BLOCKED"
    };
    let blockers = [
        (!server_pass).then_some("server_latest_path_not_pass"),
        (!client_pass).then_some("client_latest_path_not_pass"),
        (!negative_pass).then_some("negative_latest_path_not_pass"),
        (!latest_tag_parity).then_some("latest_tag_mismatch"),
        (!git_sha_parity).then_some("expected_git_sha_mismatch"),
        (!stable_channel).then_some("stable_channel_not_confirmed"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();

    json!({
        "schema_version": 1,
        "artifact": "release-latest-parity",
        "status": status,
        "verdict": if pass { "PASS" } else { "NOT_PASS" },
        "server_latest_pass": server_pass,
        "client_latest_pass": client_pass,
        "negative_latest_pass": negative_pass,
        "latest_tag_parity": latest_tag_parity,
        "expected_git_sha_parity": git_sha_parity,
        "stable_channel": stable_channel,
        "latest_tag": if latest_tag_parity { server_latest_tag } else { "" },
        "expected_git_sha": if git_sha_parity { server_git_sha } else { "" },
        "blockers": blockers,
        "inputs": {
            "server_result_json": inputs.server_result_json,
            "client_result_json": inputs.client_result_json,
            "negative_result_json": inputs.negative_result_json
        },
        "claim_boundary": {
            "latest_install_paths": "server/client/negative latest artifacts only",
            "does_not_claim": [
                "new live redeploy",
                "Windows reboot persistence",
                "Android VpnService",
                "macOS NetworkExtension",
                "broad Windows wide"
            ]
        }
    })
}

fn latest_tag(result: &Value) -> &str {
    result["latest_tag"]
        .as_str()
        .or_else(|| result["release_tag"].as_str())
        .unwrap_or_default()
}

pub fn release_latest_parity_markdown(result: &Value) -> String {
    let blockers = result["blockers"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    format!(
        "# Release Latest Parity\n\n- Status: `{}`\n- Verdict: `{}`\n- Latest tag parity: `{}`\n- Expected git SHA parity: `{}`\n- Stable channel: `{}`\n- Blockers: `{}`\n\nBoundary: latest server/client/negative artifact parity only; no new live redeploy or Phase D exit claim.\n",
        result["status"].as_str().unwrap_or("UNKNOWN"),
        result["verdict"].as_str().unwrap_or("UNKNOWN"),
        result["latest_tag_parity"].as_bool().unwrap_or(false),
        result["expected_git_sha_parity"].as_bool().unwrap_or(false),
        result["stable_channel"].as_bool().unwrap_or(false),
        if blockers.is_empty() { "none" } else { &blockers },
    )
}
