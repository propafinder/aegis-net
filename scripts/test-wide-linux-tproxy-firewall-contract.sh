#!/usr/bin/env bash
# Contract self-test for xtables/nft helper surfaces without real TPROXY.
set -euo pipefail
# The real client parser enforces owner-private config files. Keep every
# disposable positive fixture under the same permission boundary.
umask 077

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export AEGIS_ROOT_STATE_CLIENT="${AEGIS_TEST_CLIENT_BINARY:-$ROOT/target/debug/aegis-client}"
export AEGIS_MEASURE_BIN="${AEGIS_TEST_MEASURE_BINARY:-$ROOT/target/debug/aegis-measure}"

run_case() {
  local backend="$1"
  local family="$2"
  local expected_backend="$3"
  local expected_command="$4"
  local firewalld_state="${5:-not_running}"
  local listen_value="0.0.0.0:15080"
  local tmpdir=""
  local output_file=""
  local config_path=""
  local command_log=""
  local nft_state=""

  if [[ "${family}" == "ipv6" ]]; then
    listen_value="[::]:15080"
  fi

  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-helper-firewall-contract.XXXXXX")"
  export AEGIS_WIDE_FIREWALLD_STATE_FILE="${tmpdir}/firewalld.state"
  output_file="${tmpdir}/output.log"
  config_path="${tmpdir}/client.toml"
  command_log="${tmpdir}/commands.log"
  nft_state="${tmpdir}/nft.state"
  mkdir -p "${tmpdir}/bin"

  cat > "${tmpdir}/bin/iptables" <<'EOF'
#!/usr/bin/env bash
printf 'iptables %s\n' "$*" >> "${AEGIS_HELPER_FIREWALL_COMMAND_LOG}"
exit 0
EOF
  chmod +x "${tmpdir}/bin/iptables"

  cat > "${tmpdir}/bin/ip6tables" <<'EOF'
#!/usr/bin/env bash
printf 'ip6tables %s\n' "$*" >> "${AEGIS_HELPER_FIREWALL_COMMAND_LOG}"
exit 0
EOF
  chmod +x "${tmpdir}/bin/ip6tables"

  cat > "${tmpdir}/bin/firewall-cmd" <<'EOF'
#!/usr/bin/env bash
printf 'firewall-cmd %s\n' "$*" >> "${AEGIS_HELPER_FIREWALL_COMMAND_LOG}"
if [[ "${1:-}" == "--state" && "${AEGIS_HELPER_FIREWALL_FIREWALLD_STATE:-not_running}" == "running" ]]; then
  echo running
  exit 0
fi
if [[ "${AEGIS_HELPER_FIREWALL_FIREWALLD_STATE:-not_running}" != "running" ]]; then
  exit 1
fi
case "${1:-}" in
  --get-zone-of-interface=*|--get-default-zone)
    echo public
    ;;
  --get-zones)
    echo public
    ;;
  --zone=*)
    ;;
  *)
    ;;
esac
exit 0
EOF
  chmod +x "${tmpdir}/bin/firewall-cmd"

  cat > "${tmpdir}/bin/nft" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'nft %s\n' "$*" >> "${AEGIS_HELPER_FIREWALL_COMMAND_LOG}"

if [[ "${1:-}" == "list" && "${2:-}" == "chain" && "${3:-}" == "inet" && "${4:-}" == "firewalld" && "${5:-}" == "filter_INPUT" ]]; then
  if [[ "${AEGIS_HELPER_FIREWALL_FIREWALLD_STATE:-not_running}" == "running" ]]; then
    printf 'chain filter_INPUT { type filter hook input priority filter + 10; policy accept; }\n'
    exit 0
  fi
  exit 1
fi

# State is keyed PER TABLE. It used to be one flag file for every table, so
# `delete table ip <probe>` — which apply does while probing for nft support —
# cleared the marker that `ip aegis_wide_tproxy` also relied on. Whether the
# real table looked present then depended purely on the order of adds and
# deletes.
state_dir="${AEGIS_HELPER_FIREWALL_NFT_STATE}.d"
mkdir -p "${state_dir}"
table_key() { printf '%s' "${1:-}_${2:-}" | tr -c 'A-Za-z0-9_' '_'; }
case "${1:-}" in
  add)
    if [[ "${2:-}" == "table" ]]; then
      printf 'present\n' > "${state_dir}/$(table_key "${3:-}" "${4:-}")"
    fi
    exit 0
    ;;
  delete)
    if [[ "${2:-}" == "table" ]]; then
      rm -f "${state_dir}/$(table_key "${3:-}" "${4:-}")"
    fi
    exit 0
    ;;
  list)
    if [[ "${2:-}" == "table" && ! -f "${state_dir}/$(table_key "${3:-}" "${4:-}")" ]]; then
      exit 1
    fi
    if [[ "${2:-}" != "table" ]] && ! ls -1 "${state_dir}" 2>/dev/null | grep -q .; then
      exit 1
    fi
    if [[ "${2:-}" == "table" ]]; then
      cat <<LIST
table ${3} ${4} {
	chain prerouting {
		iifname "eth0" meta l4proto tcp jump AEGIS_WIDE_TPROXY comment "aegis:prerouting:tcp:AEGIS_WIDE_TPROXY"
		iifname "eth0" meta l4proto udp jump AEGIS_WIDE_TPROXY comment "aegis:prerouting:udp:AEGIS_WIDE_TPROXY"
	}
	chain AEGIS_WIDE_TPROXY {
		tcp dport 15080 return
		udp dport 15080 return
		meta l4proto tcp tproxy to :15080 meta mark set 1 accept
		meta l4proto udp tproxy to :15080 meta mark set 1 accept
	}
}
LIST
      exit 0
    fi
    if [[ "${2:-}" == "chain" ]]; then
      if [[ "${5:-}" == "prerouting" ]]; then
        cat <<LIST
chain prerouting {
	iifname "eth0" meta l4proto tcp jump AEGIS_WIDE_TPROXY comment "aegis:prerouting:tcp:AEGIS_WIDE_TPROXY"
	iifname "eth0" meta l4proto udp jump AEGIS_WIDE_TPROXY comment "aegis:prerouting:udp:AEGIS_WIDE_TPROXY"
}
LIST
      else
        cat <<LIST
chain AEGIS_WIDE_TPROXY {
	meta l4proto tcp tproxy to :15080 meta mark set 1 accept
	meta l4proto udp tproxy to :15080 meta mark set 1 accept
}
LIST
      fi
      exit 0
    fi
    ;;
esac
exit 0
EOF
  chmod +x "${tmpdir}/bin/nft"

  cat > "${tmpdir}/bin/ip" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'ip %s\n' "$*" >> "${AEGIS_HELPER_FIREWALL_COMMAND_LOG}"
if [[ "${1:-}" == "link" && "${2:-}" == "show" && "${3:-}" == "dev" ]]; then
  printf '2: %s: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n' "${4:-eth0}"
  exit 0
fi
if [[ "${1:-}" == "-4" && "${2:-}" == "-o" && "${3:-}" == "route" && "${4:-}" == "show" && "${5:-}" == "dev" ]]; then
  printf '198.18.0.0/30 dev %s proto kernel scope link src 198.18.0.1\n' "${6:-eth0}"
  exit 0
fi
if [[ "${1:-}" == "-6" && "${2:-}" == "rule" && "${3:-}" == "show" ]]; then
  printf '100: from all fwmark 1 lookup 100\n'
  exit 0
fi
if [[ "${1:-}" == "rule" && "${2:-}" == "show" ]]; then
  printf '100: from all fwmark 1 lookup 100\n'
  exit 0
fi
if [[ "${1:-}" == "-6" && "${2:-}" == "route" && "${3:-}" == "show" && "${4:-}" == "table" ]]; then
  printf 'local ::/0 dev lo metric 0 pref medium\n'
  exit 0
fi
if [[ "${1:-}" == "route" && "${2:-}" == "show" && "${3:-}" == "table" ]]; then
  printf 'local 0.0.0.0/0 dev lo scope host\n'
  exit 0
fi
exit 0
EOF
  chmod +x "${tmpdir}/bin/ip"

  cat > "${config_path}" <<EOF
mode = "relay"

[ingress]
primary = "wide"

[ingress.wide]
enabled = true
platform_backend = "linux_tproxy"
rollout_profile = "transparent_privileged"
prerouting_interface = "eth0"
listen = "${listen_value}"
capture_dns = true
udp_capture_contract = "generic_capture_unstable"
dns_port = 53
default_mark = 1
EOF

  PATH="${tmpdir}/bin:${PATH}" \
    AEGIS_HELPER_FIREWALL_COMMAND_LOG="${command_log}" \
    AEGIS_HELPER_FIREWALL_NFT_STATE="${nft_state}" \
    AEGIS_HELPER_FIREWALL_FIREWALLD_STATE="${firewalld_state}" \
    AEGIS_WIDE_FIREWALLD_STATE_FILE="${tmpdir}/firewalld.state" \
    AEGIS_WIDE_FIREWALL_BACKEND="${backend}" \
    AEGIS_WIDE_IP_FAMILY="${family}" \
    AEGIS_WIDE_INTERFACE=eth0 \
    AEGIS_ENABLE_DNS_PREVIEW=1 \
    AEGIS_UDP_CAPTURE_CONTRACT=generic_capture_unstable \
    AEGIS_CLIENT_CONFIG="${config_path}" \
    bash "${ROOT}/scripts/setup-wide-linux-tproxy.sh" apply >"${output_file}" 2>&1

  PATH="${tmpdir}/bin:${PATH}" \
    AEGIS_HELPER_FIREWALL_COMMAND_LOG="${command_log}" \
    AEGIS_HELPER_FIREWALL_NFT_STATE="${nft_state}" \
    AEGIS_HELPER_FIREWALL_FIREWALLD_STATE="${firewalld_state}" \
    AEGIS_WIDE_FIREWALLD_STATE_FILE="${tmpdir}/firewalld.state" \
    AEGIS_WIDE_FIREWALL_BACKEND="${backend}" \
    AEGIS_WIDE_IP_FAMILY="${family}" \
    AEGIS_WIDE_INTERFACE=eth0 \
    AEGIS_ENABLE_DNS_PREVIEW=1 \
    AEGIS_UDP_CAPTURE_CONTRACT=generic_capture_unstable \
    AEGIS_CLIENT_CONFIG="${config_path}" \
    bash "${ROOT}/scripts/setup-wide-linux-tproxy.sh" doctor >>"${output_file}" 2>&1 || {
      # Print what happened. Without this the helper's failure kills the
      # contract through `set -e` before any assertion runs, and CI shows a
      # bare "Process completed with exit code 1" with no diagnostics — which
      # is exactly how this step sat broken and unreadable on main.
      doctor_status=$?
      echo "helper doctor exited ${doctor_status} (backend=${backend} family=${family})" >&2
      echo "--- captured helper output ---" >&2
      sed -n '1,320p' "${output_file}" >&2 || true
      echo "--- end helper output ---" >&2
      rm -rf "${tmpdir}"
      exit 1
    }

  PATH="${tmpdir}/bin:${PATH}" \
    AEGIS_HELPER_FIREWALL_COMMAND_LOG="${command_log}" \
    AEGIS_HELPER_FIREWALL_NFT_STATE="${nft_state}" \
    AEGIS_HELPER_FIREWALL_FIREWALLD_STATE="${firewalld_state}" \
    AEGIS_WIDE_FIREWALLD_STATE_FILE="${tmpdir}/firewalld.state" \
    AEGIS_WIDE_FIREWALL_BACKEND="${backend}" \
    AEGIS_WIDE_IP_FAMILY="${family}" \
    AEGIS_WIDE_INTERFACE=eth0 \
    AEGIS_ENABLE_DNS_PREVIEW=1 \
    AEGIS_UDP_CAPTURE_CONTRACT=generic_capture_unstable \
    AEGIS_CLIENT_CONFIG="${config_path}" \
    bash "${ROOT}/scripts/setup-wide-linux-tproxy.sh" status >>"${output_file}" 2>&1 || {
      helper_status=$?
      echo "helper status exited ${helper_status} (backend=${backend} family=${family})" >&2
      sed -n '1,320p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
    }

  PATH="${tmpdir}/bin:${PATH}" \
    AEGIS_HELPER_FIREWALL_COMMAND_LOG="${command_log}" \
    AEGIS_HELPER_FIREWALL_NFT_STATE="${nft_state}" \
    AEGIS_HELPER_FIREWALL_FIREWALLD_STATE="${firewalld_state}" \
    AEGIS_WIDE_FIREWALLD_STATE_FILE="${tmpdir}/firewalld.state" \
    AEGIS_WIDE_FIREWALL_BACKEND="${backend}" \
    AEGIS_WIDE_IP_FAMILY="${family}" \
    AEGIS_WIDE_INTERFACE=eth0 \
    AEGIS_ENABLE_DNS_PREVIEW=1 \
    AEGIS_UDP_CAPTURE_CONTRACT=generic_capture_unstable \
    bash "${ROOT}/scripts/setup-wide-linux-tproxy.sh" teardown >>"${output_file}" 2>&1

  case "$(sed -n '1,320p' "${output_file}")" in
    *"ssh_safe_ports=22"* ) ;;
    *)
      echo "missing ssh-safe ports summary for backend=${backend} family=${family}" >&2
      sed -n '1,320p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  case "$(sed -n '1,320p' "${command_log}")" in
    *"--dport 22 -j RETURN"*|*"tcp dport 22 return"* ) ;;
    *)
      echo "missing ssh-safe RETURN rule for backend=${backend} family=${family}" >&2
      sed -n '1,320p' "${command_log}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  case "$(sed -n '1,320p' "${output_file}")" in
    *"firewall_backend=${expected_backend}"* ) ;;
    *)
      echo "missing firewall backend summary ${expected_backend} for backend=${backend} family=${family}" >&2
      sed -n '1,320p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  case "$(sed -n '1,320p' "${output_file}")" in
    *"Doctor result: host contract looks consistent for linux_tproxy"* ) ;;
    *)
      echo "doctor summary mismatch for backend=${backend} family=${family}" >&2
      sed -n '1,320p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  case "$(sed -n '1,320p' "${output_file}")" in
    *"config_udp_capture_support_tier=guarded_unstable"* ) ;;
    *)
      echo "missing config support tier summary for backend=${backend} family=${family}" >&2
      sed -n '1,320p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  case "$(sed -n '1,320p' "${output_file}")" in
    *"config_udp_capture_policy="* ) ;;
    *)
      echo "missing config policy summary for backend=${backend} family=${family}" >&2
      sed -n '1,320p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  case "$(sed -n '1,320p' "${output_file}")" in
    *"UDP capture runtime scope matches client config"* ) ;;
    *)
      echo "missing runtime scope doctor check for backend=${backend} family=${family}" >&2
      sed -n '1,320p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  case "$(sed -n '1,320p' "${output_file}")" in
    *"dns_port=<ignored_by_generic_capture_contract>"* ) ;;
    *)
      echo "missing generic-contract dns_port ignore summary for backend=${backend} family=${family}" >&2
      sed -n '1,320p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  case "$(sed -n '1,320p' "${output_file}")" in
    *"udp_preview_ports=<ignored_by_generic_capture_contract>"* ) ;;
    *)
      echo "missing generic-contract udp_preview_ports ignore summary for backend=${backend} family=${family}" >&2
      sed -n '1,320p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  case "$(sed -n '1,200p' "${command_log}")" in
    *"${expected_command}"* ) ;;
    *)
      echo "expected command '${expected_command}' was not executed for backend=${backend} family=${family}" >&2
      sed -n '1,200p' "${command_log}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  local expected_filter_bin="iptables"
  if [[ "${family}" == "ipv6" ]]; then
    expected_filter_bin="ip6tables"
  fi
  local commands=""
  commands="$(sed -n '1,360p' "${command_log}")"
  local expected_filter_command=""
  for expected_filter_command in \
    "${expected_filter_bin} -t filter -N AEGIS_WIDE_TPROXY_IN" \
    "${expected_filter_bin} -t filter -A AEGIS_WIDE_TPROXY_IN -p tcp -m mark --mark 1/1 -j ACCEPT" \
    "${expected_filter_bin} -t filter -A AEGIS_WIDE_TPROXY_IN -p udp -m mark --mark 1/1 -j ACCEPT" \
    "${expected_filter_bin} -t filter -I INPUT 1 -i eth0 -j AEGIS_WIDE_TPROXY_IN" \
    "${expected_filter_bin} -t filter -D INPUT -i eth0 -j AEGIS_WIDE_TPROXY_IN"; do
    case "${commands}" in
      *"${expected_filter_command}"* ) ;;
      *)
        echo "missing INPUT delivery command '${expected_filter_command}' for backend=${backend} family=${family}" >&2
        printf '%s\n' "${commands}" >&2
        rm -rf "${tmpdir}"
        exit 1
        ;;
    esac
  done

  if [[ "${firewalld_state}" == "running" ]]; then
    for expected_filter_command in \
      "iptables -t filter -A AEGIS_WIDE_TPROXY_IN -p tcp -j DROP" \
      "iptables -t filter -A AEGIS_WIDE_TPROXY_IN -p udp -j DROP" \
      "firewall-cmd --zone=public --add-rich-rule=rule family=\"ipv4\" source address=\"198.18.0.0/30\" port port=\"1-21\" protocol=\"tcp\" accept" \
      "firewall-cmd --zone=public --add-rich-rule=rule family=\"ipv4\" source address=\"198.18.0.0/30\" port port=\"1-15079\" protocol=\"udp\" accept" \
      "firewall-cmd --zone=public --remove-rich-rule=rule family=\"ipv4\" source address=\"198.18.0.0/30\" port port=\"1-21\" protocol=\"tcp\" accept"; do
      case "${commands}" in
        *"${expected_filter_command}"* ) ;;
        *)
          echo "missing firewalld compatibility command '${expected_filter_command}'" >&2
          printf '%s\n' "${commands}" >&2
          rm -rf "${tmpdir}"
          exit 1
          ;;
      esac
    done
  fi

  if [[ "${backend}" == "xtables" && "${family}" == "ipv6" ]]; then
    case "$(sed -n '1,240p' "${command_log}")" in
      *"--on-ip ::"* ) ;;
      *)
        echo "expected explicit IPv6 TPROXY on-ip contract for ip6tables helper" >&2
        sed -n '1,240p' "${command_log}" >&2 || true
        rm -rf "${tmpdir}"
        exit 1
        ;;
    esac
  fi

  if [[ "${family}" == "ipv6" ]]; then
    case "$(sed -n '1,240p' "${command_log}")" in
      *"ip -6 rule add fwmark 1 lookup 100"* ) ;;
      *)
        echo "expected IPv6 policy rule add command for backend=${backend} family=${family}" >&2
        sed -n '1,240p' "${command_log}" >&2 || true
        rm -rf "${tmpdir}"
        exit 1
        ;;
    esac
    case "$(sed -n '1,240p' "${command_log}")" in
      *"ip -6 route add local ::/0 dev lo table 100"* ) ;;
      *)
        echo "expected IPv6 policy route add command for backend=${backend} family=${family}" >&2
        sed -n '1,240p' "${command_log}" >&2 || true
        rm -rf "${tmpdir}"
        exit 1
        ;;
    esac
  else
    case "$(sed -n '1,240p' "${command_log}")" in
      *"ip rule add fwmark 1 lookup 100"* ) ;;
      *)
        echo "expected IPv4 policy rule add command for backend=${backend} family=${family}" >&2
        sed -n '1,240p' "${command_log}" >&2 || true
        rm -rf "${tmpdir}"
        exit 1
        ;;
    esac
    case "$(sed -n '1,240p' "${command_log}")" in
      *"ip route add local 0.0.0.0/0 dev lo table 100"* ) ;;
      *)
        echo "expected IPv4 policy route add command for backend=${backend} family=${family}" >&2
        sed -n '1,240p' "${command_log}" >&2 || true
        rm -rf "${tmpdir}"
        exit 1
        ;;
    esac
  fi

  rm -rf "${tmpdir}"
}

run_rollout_profile_mismatch_case() {
  local tmpdir=""
  local output_file=""
  local config_path=""
  local command_log=""
  local nft_state=""

  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-helper-firewall-contract.XXXXXX")"
  export AEGIS_WIDE_FIREWALLD_STATE_FILE="${tmpdir}/firewalld.state"
  output_file="${tmpdir}/output.log"
  config_path="${tmpdir}/client.toml"
  command_log="${tmpdir}/commands.log"
  nft_state="${tmpdir}/nft.state"
  mkdir -p "${tmpdir}/bin"

  cat > "${tmpdir}/bin/iptables" <<'EOF'
#!/usr/bin/env bash
printf 'iptables %s\n' "$*" >> "${AEGIS_HELPER_FIREWALL_COMMAND_LOG}"
exit 0
EOF
  chmod +x "${tmpdir}/bin/iptables"

  cat > "${tmpdir}/bin/ip6tables" <<'EOF'
#!/usr/bin/env bash
printf 'ip6tables %s\n' "$*" >> "${AEGIS_HELPER_FIREWALL_COMMAND_LOG}"
exit 0
EOF
  chmod +x "${tmpdir}/bin/ip6tables"

  cat > "${tmpdir}/bin/nft" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${tmpdir}/bin/nft"

  cat > "${tmpdir}/bin/ip" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "link" && "${2:-}" == "show" && "${3:-}" == "dev" ]]; then
  printf '2: %s: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n' "${4:-eth0}"
  exit 0
fi
if [[ "${1:-}" == "rule" && "${2:-}" == "show" ]]; then
  printf '100: from all fwmark 1 lookup 100\n'
  exit 0
fi
if [[ "${1:-}" == "route" && "${2:-}" == "show" && "${3:-}" == "table" ]]; then
  printf 'local 0.0.0.0/0 dev lo scope host\n'
  exit 0
fi
exit 0
EOF
  chmod +x "${tmpdir}/bin/ip"

  cat > "${config_path}" <<'EOF'
mode = "relay"

[ingress]
primary = "wide"

[ingress.wide]
enabled = true
platform_backend = "linux_tproxy"
rollout_profile = "prerouting_scoped"
prerouting_interface = "eth0"
listen = "0.0.0.0:15080"
capture_dns = true
udp_capture_contract = "preview_allowlist_only"
dns_port = 53
default_mark = 1
EOF

  if PATH="${tmpdir}/bin:${PATH}" \
    AEGIS_HELPER_FIREWALL_COMMAND_LOG="${command_log}" \
    AEGIS_HELPER_FIREWALL_NFT_STATE="${nft_state}" \
    AEGIS_WIDE_FIREWALL_BACKEND=xtables \
    AEGIS_WIDE_IP_FAMILY=ipv4 \
    AEGIS_WIDE_INTERFACE=eth0 \
    AEGIS_ENABLE_DNS_PREVIEW=1 \
    AEGIS_CLIENT_CONFIG="${config_path}" \
    bash "${ROOT}/scripts/setup-wide-linux-tproxy.sh" apply >"${output_file}" 2>&1; then
    echo "apply unexpectedly succeeded for rollout profile mismatch" >&2
    sed -n '1,240p' "${output_file}" >&2 || true
    rm -rf "${tmpdir}"
    exit 1
  fi
  if ! grep -q 'selected client is not configured for active privileged Linux TPROXY; refusing apply' "${output_file}"; then
    echo "missing apply rollout profile refusal" >&2
    sed -n '1,240p' "${output_file}" >&2 || true
    rm -rf "${tmpdir}"
    exit 1
  fi
  if [[ -s "${command_log}" ]]; then
    echo "apply mutated firewall before refusing rollout profile mismatch" >&2
    sed -n '1,240p' "${command_log}" >&2 || true
    rm -rf "${tmpdir}"
    exit 1
  fi

  if PATH="${tmpdir}/bin:${PATH}" \
    AEGIS_HELPER_FIREWALL_COMMAND_LOG="${command_log}" \
    AEGIS_HELPER_FIREWALL_NFT_STATE="${nft_state}" \
    AEGIS_WIDE_FIREWALL_BACKEND=xtables \
    AEGIS_WIDE_IP_FAMILY=ipv4 \
    AEGIS_WIDE_INTERFACE=eth0 \
    AEGIS_ENABLE_DNS_PREVIEW=1 \
    AEGIS_CLIENT_CONFIG="${config_path}" \
    bash "${ROOT}/scripts/setup-wide-linux-tproxy.sh" doctor >>"${output_file}" 2>&1; then
    echo "doctor unexpectedly succeeded for rollout profile mismatch" >&2
    sed -n '1,240p' "${output_file}" >&2 || true
    rm -rf "${tmpdir}"
    exit 1
  fi

  case "$(sed -n '1,240p' "${output_file}")" in
    *"client rollout profile prerouting_scoped is not compatible with TPROXY helper scope"* ) ;;
    *)
      echo "missing rollout profile mismatch diagnostic" >&2
      sed -n '1,240p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  rm -rf "${tmpdir}"
}

run_family_mismatch_case() {
  local tmpdir=""
  local output_file=""
  local config_path=""

  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-helper-firewall-contract.XXXXXX")"
  export AEGIS_WIDE_FIREWALLD_STATE_FILE="${tmpdir}/firewalld.state"
  output_file="${tmpdir}/output.log"
  config_path="${tmpdir}/client.toml"
  mkdir -p "${tmpdir}/bin"

  cat > "${tmpdir}/bin/iptables" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${tmpdir}/bin/iptables"

  cat > "${tmpdir}/bin/ip6tables" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${tmpdir}/bin/ip6tables"

  cat > "${tmpdir}/bin/nft" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${tmpdir}/bin/nft"

  cat > "${tmpdir}/bin/ip" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${tmpdir}/bin/ip"

  cat > "${config_path}" <<'EOF'
mode = "relay"

[ingress]
primary = "wide"

[ingress.wide]
enabled = true
platform_backend = "linux_tproxy"
rollout_profile = "transparent_privileged"
prerouting_interface = "eth0"
listen = "[::]:15080"
capture_dns = true
udp_capture_contract = "generic_capture_unstable"
dns_port = 53
default_mark = 1
EOF

  if PATH="${tmpdir}/bin:${PATH}" \
    AEGIS_WIDE_FIREWALL_BACKEND=xtables \
    AEGIS_WIDE_IP_FAMILY=ipv4 \
    AEGIS_WIDE_INTERFACE=eth0 \
    AEGIS_ENABLE_DNS_PREVIEW=1 \
    AEGIS_UDP_CAPTURE_CONTRACT=generic_capture_unstable \
    AEGIS_CLIENT_CONFIG="${config_path}" \
    bash "${ROOT}/scripts/setup-wide-linux-tproxy.sh" apply >"${output_file}" 2>&1; then
    echo "apply unexpectedly succeeded for family mismatch" >&2
    sed -n '1,160p' "${output_file}" >&2 || true
    rm -rf "${tmpdir}"
    exit 1
  fi

  case "$(sed -n '1,160p' "${output_file}")" in
    *"AEGIS_WIDE_IP_FAMILY=ipv4 does not match client listen family ipv6"* ) ;;
    *)
      echo "missing family mismatch diagnostic" >&2
      sed -n '1,160p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  rm -rf "${tmpdir}"
}

run_iproute2_output_variant_case() {
  local tmpdir=""
  local output_file=""
  local config_path=""
  local command_log=""
  local nft_state=""

  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-helper-firewall-contract.XXXXXX")"
  export AEGIS_WIDE_FIREWALLD_STATE_FILE="${tmpdir}/firewalld.state"
  output_file="${tmpdir}/output.log"
  config_path="${tmpdir}/client.toml"
  command_log="${tmpdir}/commands.log"
  nft_state="${tmpdir}/nft.state"
  mkdir -p "${tmpdir}/bin"

  cat > "${tmpdir}/bin/iptables" <<'EOF'
#!/usr/bin/env bash
printf 'iptables %s\n' "$*" >> "${AEGIS_HELPER_FIREWALL_COMMAND_LOG}"
exit 0
EOF
  chmod +x "${tmpdir}/bin/iptables"

  cat > "${tmpdir}/bin/ip6tables" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${tmpdir}/bin/ip6tables"

  cat > "${tmpdir}/bin/nft" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${tmpdir}/bin/nft"

  cat > "${tmpdir}/bin/ip" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'ip %s\n' "$*" >> "${AEGIS_HELPER_FIREWALL_COMMAND_LOG}"
if [[ "${1:-}" == "link" && "${2:-}" == "show" && "${3:-}" == "dev" ]]; then
  printf '2: %s: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n' "${4:-eth0}"
  exit 0
fi
if [[ "${1:-}" == "rule" && "${2:-}" == "show" ]]; then
  printf '0: from all lookup local\n'
  printf '32765: from all fwmark 0x1 lookup 100\n'
  printf '32766: from all lookup main\n'
  exit 0
fi
if [[ "${1:-}" == "route" && "${2:-}" == "show" && "${3:-}" == "table" ]]; then
  printf 'local default dev lo scope host\n'
  exit 0
fi
exit 0
EOF
  chmod +x "${tmpdir}/bin/ip"

  cat > "${config_path}" <<'EOF'
mode = "relay"

[ingress]
primary = "wide"

[ingress.wide]
enabled = true
platform_backend = "linux_tproxy"
rollout_profile = "transparent_privileged"
prerouting_interface = "eth0"
listen = "0.0.0.0:15080"
capture_dns = true
udp_capture_contract = "generic_capture_unstable"
dns_port = 53
default_mark = 1
EOF

  PATH="${tmpdir}/bin:${PATH}" \
    AEGIS_HELPER_FIREWALL_COMMAND_LOG="${command_log}" \
    AEGIS_HELPER_FIREWALL_NFT_STATE="${nft_state}" \
    AEGIS_WIDE_FIREWALL_BACKEND=xtables \
    AEGIS_WIDE_IP_FAMILY=ipv4 \
    AEGIS_WIDE_INTERFACE=eth0 \
    AEGIS_ENABLE_DNS_PREVIEW=1 \
    AEGIS_UDP_CAPTURE_CONTRACT=generic_capture_unstable \
    AEGIS_CLIENT_CONFIG="${config_path}" \
    bash "${ROOT}/scripts/setup-wide-linux-tproxy.sh" apply >"${output_file}" 2>&1

  PATH="${tmpdir}/bin:${PATH}" \
    AEGIS_HELPER_FIREWALL_COMMAND_LOG="${command_log}" \
    AEGIS_HELPER_FIREWALL_NFT_STATE="${nft_state}" \
    AEGIS_WIDE_FIREWALL_BACKEND=xtables \
    AEGIS_WIDE_IP_FAMILY=ipv4 \
    AEGIS_WIDE_INTERFACE=eth0 \
    AEGIS_ENABLE_DNS_PREVIEW=1 \
    AEGIS_UDP_CAPTURE_CONTRACT=generic_capture_unstable \
    AEGIS_CLIENT_CONFIG="${config_path}" \
    bash "${ROOT}/scripts/setup-wide-linux-tproxy.sh" doctor >>"${output_file}" 2>&1

  case "$(sed -n '1,240p' "${output_file}")" in
    *"Doctor result: host contract looks consistent for linux_tproxy"* ) ;;
    *)
      echo "doctor did not tolerate iproute2 output variants" >&2
      sed -n '1,240p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  rm -rf "${tmpdir}"
}

run_missing_interface_case() {
  local tmpdir=""
  local output_file=""
  local config_path=""

  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-helper-firewall-contract.XXXXXX")"
  export AEGIS_WIDE_FIREWALLD_STATE_FILE="${tmpdir}/firewalld.state"
  output_file="${tmpdir}/output.log"
  config_path="${tmpdir}/client.toml"
  mkdir -p "${tmpdir}/bin"

  cat > "${tmpdir}/bin/iptables" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${tmpdir}/bin/iptables"

  cat > "${tmpdir}/bin/ip6tables" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${tmpdir}/bin/ip6tables"

  cat > "${tmpdir}/bin/nft" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${tmpdir}/bin/nft"

  cat > "${tmpdir}/bin/ip" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "route" && "${2:-}" == "show" && "${3:-}" == "default" ]]; then
  printf 'default via 198.18.0.1 dev eth0 proto static\n'
  exit 0
fi
exit 0
EOF
  chmod +x "${tmpdir}/bin/ip"

  cat > "${config_path}" <<'EOF'
mode = "relay"

[ingress]
primary = "wide"

[ingress.wide]
enabled = true
platform_backend = "linux_tproxy"
rollout_profile = "transparent_privileged"
prerouting_interface = "eth0"
listen = "0.0.0.0:15080"
capture_dns = true
udp_capture_contract = "preview_allowlist_only"
dns_port = 53
default_mark = 1
EOF

  if PATH="${tmpdir}/bin:${PATH}" \
    AEGIS_WIDE_FIREWALL_BACKEND=xtables \
    AEGIS_WIDE_IP_FAMILY=ipv4 \
    AEGIS_ENABLE_DNS_PREVIEW=1 \
    AEGIS_CLIENT_CONFIG="${config_path}" \
    bash "${ROOT}/scripts/setup-wide-linux-tproxy.sh" apply >"${output_file}" 2>&1; then
    echo "apply unexpectedly succeeded without explicit interface scope" >&2
    sed -n '1,200p' "${output_file}" >&2 || true
    rm -rf "${tmpdir}"
    exit 1
  fi

  case "$(sed -n '1,200p' "${output_file}")" in
    *"AEGIS_WIDE_INTERFACE is required for the supported linux_tproxy helper path"* ) ;;
    *)
      echo "missing explicit-interface requirement diagnostic" >&2
      sed -n '1,200p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  case "$(sed -n '1,200p' "${output_file}")" in
    *"Assisted detect: Linux default route suggests interface eth0"* ) ;;
    *)
      echo "missing assisted interface suggestion for unset interface case" >&2
      sed -n '1,200p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  case "$(sed -n '1,200p' "${output_file}")" in
    *"AEGIS_WIDE_ALLOW_ALL_INTERFACES=1"* ) ;;
    *)
      echo "missing unsafe all-interface opt-in diagnostic" >&2
      sed -n '1,200p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  rm -rf "${tmpdir}"
}

run_allow_all_interfaces_opt_in_case() {
  local tmpdir=""
  local output_file=""
  local config_path=""
  local command_log=""

  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-helper-firewall-contract.XXXXXX")"
  export AEGIS_WIDE_FIREWALLD_STATE_FILE="${tmpdir}/firewalld.state"
  output_file="${tmpdir}/output.log"
  config_path="${tmpdir}/client.toml"
  command_log="${tmpdir}/commands.log"
  mkdir -p "${tmpdir}/bin"

  cat > "${tmpdir}/bin/iptables" <<'EOF'
#!/usr/bin/env bash
printf 'iptables %s\n' "$*" >> "${AEGIS_HELPER_FIREWALL_COMMAND_LOG}"
exit 0
EOF
  chmod +x "${tmpdir}/bin/iptables"

  cat > "${tmpdir}/bin/ip6tables" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${tmpdir}/bin/ip6tables"

  cat > "${tmpdir}/bin/nft" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${tmpdir}/bin/nft"

  cat > "${tmpdir}/bin/ip" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "route" && "${2:-}" == "show" && "${3:-}" == "default" ]]; then
  printf 'default via 198.18.0.1 dev eth0 proto static\n'
  exit 0
fi
if [[ "${1:-}" == "rule" && "${2:-}" == "show" ]]; then
  printf '100: from all fwmark 1 lookup 100\n'
  exit 0
fi
if [[ "${1:-}" == "route" && "${2:-}" == "show" && "${3:-}" == "table" ]]; then
  printf 'local 0.0.0.0/0 dev lo scope host\n'
  exit 0
fi
if [[ "${1:-}" == "rule" && "${2:-}" == "add" ]]; then
  exit 0
fi
if [[ "${1:-}" == "route" && "${2:-}" == "add" ]]; then
  exit 0
fi
if [[ "${1:-}" == "rule" && "${2:-}" == "del" ]]; then
  exit 0
fi
if [[ "${1:-}" == "route" && "${2:-}" == "del" ]]; then
  exit 0
fi
exit 0
EOF
  chmod +x "${tmpdir}/bin/ip"

  cat > "${config_path}" <<'EOF'
mode = "relay"

[ingress]
primary = "wide"

[ingress.wide]
enabled = true
platform_backend = "linux_tproxy"
rollout_profile = "transparent_privileged"
listen = "0.0.0.0:15080"
capture_dns = true
udp_capture_contract = "preview_allowlist_only"
dns_port = 53
default_mark = 1
EOF

  if PATH="${tmpdir}/bin:${PATH}" \
    AEGIS_HELPER_FIREWALL_COMMAND_LOG="${command_log}" \
    AEGIS_WIDE_FIREWALL_BACKEND=xtables \
    AEGIS_WIDE_IP_FAMILY=ipv4 \
    AEGIS_WIDE_ALLOW_ALL_INTERFACES=1 \
    AEGIS_ENABLE_DNS_PREVIEW=1 \
    AEGIS_CLIENT_CONFIG="" \
    bash "${ROOT}/scripts/setup-wide-linux-tproxy.sh" apply >"${output_file}" 2>&1; then
    echo "apply unexpectedly succeeded without client config in unsafe all-interface mode" >&2
    sed -n '1,240p' "${output_file}" >&2 || true
    rm -rf "${tmpdir}"
    exit 1
  fi

  case "$(sed -n '1,240p' "${output_file}")" in
    *"AEGIS_CLIENT_CONFIG is required; refusing apply"* ) ;;
    *)
      echo "missing client config refusal for unsafe all-interface mode" >&2
      sed -n '1,240p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  if [[ -s "${command_log}" ]]; then
    echo "unsafe all-interface apply touched firewall without client config" >&2
    sed -n '1,200p' "${command_log}" >&2 || true
    rm -rf "${tmpdir}"
    exit 1
  fi

  rm -rf "${tmpdir}"
}

run_policy_routing_duplicate_state_case() {
  local tmpdir=""
  local output_file=""
  local config_path=""
  local command_log=""

  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-helper-firewall-contract.XXXXXX")"
  export AEGIS_WIDE_FIREWALLD_STATE_FILE="${tmpdir}/firewalld.state"
  output_file="${tmpdir}/output.log"
  config_path="${tmpdir}/client.toml"
  command_log="${tmpdir}/commands.log"
  mkdir -p "${tmpdir}/bin"

  cat > "${tmpdir}/bin/iptables" <<'EOF'
#!/usr/bin/env bash
printf 'iptables %s\n' "$*" >> "${AEGIS_HELPER_FIREWALL_COMMAND_LOG}"
exit 0
EOF
  chmod +x "${tmpdir}/bin/iptables"

  cat > "${tmpdir}/bin/ip6tables" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${tmpdir}/bin/ip6tables"

  cat > "${tmpdir}/bin/nft" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${tmpdir}/bin/nft"

  cat > "${tmpdir}/bin/ip" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'ip %s\n' "$*" >> "${AEGIS_HELPER_FIREWALL_COMMAND_LOG}"
if [[ "${1:-}" == "rule" && "${2:-}" == "add" ]]; then
  echo "RTNETLINK answers: File exists" >&2
  exit 2
fi
if [[ "${1:-}" == "route" && "${2:-}" == "add" ]]; then
  echo "RTNETLINK answers: File exists" >&2
  exit 2
fi
if [[ "${1:-}" == "rule" && "${2:-}" == "show" ]]; then
  printf '100: from all fwmark 1 lookup 100\n'
  exit 0
fi
if [[ "${1:-}" == "route" && "${2:-}" == "show" && "${3:-}" == "table" ]]; then
  printf 'local 0.0.0.0/0 dev lo scope host\n'
  exit 0
fi
if [[ "${1:-}" == "rule" && "${2:-}" == "del" ]]; then
  exit 0
fi
if [[ "${1:-}" == "route" && "${2:-}" == "del" ]]; then
  exit 0
fi
exit 0
EOF
  chmod +x "${tmpdir}/bin/ip"

  cat > "${config_path}" <<'EOF'
mode = "relay"

[ingress]
primary = "wide"

[ingress.wide]
enabled = true
platform_backend = "linux_tproxy"
rollout_profile = "transparent_privileged"
prerouting_interface = "eth0"
listen = "0.0.0.0:15080"
capture_dns = true
udp_capture_contract = "preview_allowlist_only"
dns_port = 53
default_mark = 1
EOF

  PATH="${tmpdir}/bin:${PATH}" \
    AEGIS_HELPER_FIREWALL_COMMAND_LOG="${command_log}" \
    AEGIS_WIDE_FIREWALL_BACKEND=xtables \
    AEGIS_WIDE_IP_FAMILY=ipv4 \
    AEGIS_WIDE_INTERFACE=eth0 \
    AEGIS_ENABLE_DNS_PREVIEW=1 \
    AEGIS_CLIENT_CONFIG="${config_path}" \
    bash "${ROOT}/scripts/setup-wide-linux-tproxy.sh" apply >"${output_file}" 2>&1

  case "$(sed -n '1,240p' "${output_file}")" in
    *"WARN: ip rule add reported: RTNETLINK answers: File exists"* ) ;;
    *)
      echo "missing duplicate policy-rule warning" >&2
      sed -n '1,240p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  case "$(sed -n '1,240p' "${output_file}")" in
    *"WARN: ip route add reported: RTNETLINK answers: File exists"* ) ;;
    *)
      echo "missing duplicate policy-route warning" >&2
      sed -n '1,240p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  case "$(sed -n '1,240p' "${output_file}")" in
    *"Policy routing contract is ready: fwmark 1 -> table 100"* ) ;;
    *)
      echo "missing ready policy-routing summary for duplicate state case" >&2
      sed -n '1,240p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  rm -rf "${tmpdir}"
}

run_policy_routing_failure_case() {
  local tmpdir=""
  local output_file=""
  local config_path=""
  local command_log=""

  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-helper-firewall-contract.XXXXXX")"
  export AEGIS_WIDE_FIREWALLD_STATE_FILE="${tmpdir}/firewalld.state"
  output_file="${tmpdir}/output.log"
  config_path="${tmpdir}/client.toml"
  command_log="${tmpdir}/commands.log"
  mkdir -p "${tmpdir}/bin"

  cat > "${tmpdir}/bin/iptables" <<'EOF'
#!/usr/bin/env bash
printf 'iptables %s\n' "$*" >> "${AEGIS_HELPER_FIREWALL_COMMAND_LOG}"
exit 0
EOF
  chmod +x "${tmpdir}/bin/iptables"

  cat > "${tmpdir}/bin/ip6tables" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${tmpdir}/bin/ip6tables"

  cat > "${tmpdir}/bin/nft" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${tmpdir}/bin/nft"

  cat > "${tmpdir}/bin/ip" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'ip %s\n' "$*" >> "${AEGIS_HELPER_FIREWALL_COMMAND_LOG}"
if [[ "${1:-}" == "rule" && "${2:-}" == "add" ]]; then
  echo "RTNETLINK answers: Operation not permitted" >&2
  exit 2
fi
if [[ "${1:-}" == "route" && "${2:-}" == "add" ]]; then
  echo "RTNETLINK answers: Operation not permitted" >&2
  exit 2
fi
if [[ "${1:-}" == "rule" && "${2:-}" == "show" ]]; then
  exit 0
fi
if [[ "${1:-}" == "route" && "${2:-}" == "show" && "${3:-}" == "table" ]]; then
  exit 0
fi
if [[ "${1:-}" == "rule" && "${2:-}" == "del" ]]; then
  exit 0
fi
if [[ "${1:-}" == "route" && "${2:-}" == "del" ]]; then
  exit 0
fi
exit 0
EOF
  chmod +x "${tmpdir}/bin/ip"

  cat > "${config_path}" <<'EOF'
mode = "relay"

[ingress]
primary = "wide"

[ingress.wide]
enabled = true
platform_backend = "linux_tproxy"
rollout_profile = "transparent_privileged"
prerouting_interface = "eth0"
listen = "0.0.0.0:15080"
capture_dns = true
udp_capture_contract = "preview_allowlist_only"
dns_port = 53
default_mark = 1
EOF

  if PATH="${tmpdir}/bin:${PATH}" \
    AEGIS_HELPER_FIREWALL_COMMAND_LOG="${command_log}" \
    AEGIS_WIDE_FIREWALL_BACKEND=xtables \
    AEGIS_WIDE_IP_FAMILY=ipv4 \
    AEGIS_WIDE_INTERFACE=eth0 \
    AEGIS_ENABLE_DNS_PREVIEW=1 \
    AEGIS_CLIENT_CONFIG="${config_path}" \
    bash "${ROOT}/scripts/setup-wide-linux-tproxy.sh" apply >"${output_file}" 2>&1; then
    echo "apply unexpectedly succeeded for missing policy-routing state" >&2
    sed -n '1,240p' "${output_file}" >&2 || true
    rm -rf "${tmpdir}"
    exit 1
  fi

  case "$(sed -n '1,240p' "${output_file}")" in
    *"Failed to materialize required fwmark rule 1 -> table 100"* ) ;;
    *)
      echo "missing policy-rule materialization failure" >&2
      sed -n '1,240p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  case "$(sed -n '1,240p' "${output_file}")" in
    *"Policy-routing apply failed; rolling back helper state"* ) ;;
    *)
      echo "missing policy-routing rollback message" >&2
      sed -n '1,240p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  case "$(sed -n '1,240p' "${command_log}")" in
    *"ip rule del fwmark 1 lookup 100"* ) ;;
    *)
      echo "expected policy-rule rollback command after apply failure" >&2
      sed -n '1,240p' "${command_log}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  case "$(sed -n '1,240p' "${command_log}")" in
    *"ip route del local 0.0.0.0/0 dev lo table 100"* ) ;;
    *)
      echo "expected policy-route rollback command after apply failure" >&2
      sed -n '1,240p' "${command_log}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  rm -rf "${tmpdir}"
}

run_generic_contract_ignores_preview_drift_case() {
  local tmpdir=""
  local output_file=""
  local config_path=""
  local command_log=""
  local nft_state=""

  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-helper-firewall-contract.XXXXXX")"
  export AEGIS_WIDE_FIREWALLD_STATE_FILE="${tmpdir}/firewalld.state"
  output_file="${tmpdir}/output.log"
  config_path="${tmpdir}/client.toml"
  command_log="${tmpdir}/commands.log"
  nft_state="${tmpdir}/nft.state"
  mkdir -p "${tmpdir}/bin"

  cat > "${tmpdir}/bin/iptables" <<'EOF'
#!/usr/bin/env bash
printf 'iptables %s\n' "$*" >> "${AEGIS_HELPER_FIREWALL_COMMAND_LOG}"
exit 0
EOF
  chmod +x "${tmpdir}/bin/iptables"

  cat > "${tmpdir}/bin/ip6tables" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${tmpdir}/bin/ip6tables"

  cat > "${tmpdir}/bin/nft" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${tmpdir}/bin/nft"

  cat > "${tmpdir}/bin/ip" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'ip %s\n' "$*" >> "${AEGIS_HELPER_FIREWALL_COMMAND_LOG}"
if [[ "${1:-}" == "link" && "${2:-}" == "show" && "${3:-}" == "dev" ]]; then
  printf '2: %s: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n' "${4:-eth0}"
  exit 0
fi
if [[ "${1:-}" == "rule" && "${2:-}" == "show" ]]; then
  printf '100: from all fwmark 1 lookup 100\n'
  exit 0
fi
if [[ "${1:-}" == "route" && "${2:-}" == "show" && "${3:-}" == "table" ]]; then
  printf 'local 0.0.0.0/0 dev lo scope host\n'
  exit 0
fi
exit 0
EOF
  chmod +x "${tmpdir}/bin/ip"

  cat > "${config_path}" <<'EOF'
mode = "relay"

[ingress]
primary = "wide"

[ingress.wide]
enabled = true
platform_backend = "linux_tproxy"
rollout_profile = "transparent_privileged"
prerouting_interface = "eth0"
listen = "0.0.0.0:15080"
capture_dns = true
udp_capture_contract = "generic_capture_unstable"
dns_port = 5300
udp_preview_ports = [5353, 853]
default_mark = 1
EOF

  PATH="${tmpdir}/bin:${PATH}" \
    AEGIS_HELPER_FIREWALL_COMMAND_LOG="${command_log}" \
    AEGIS_HELPER_FIREWALL_NFT_STATE="${nft_state}" \
    AEGIS_WIDE_FIREWALL_BACKEND=xtables \
    AEGIS_WIDE_IP_FAMILY=ipv4 \
    AEGIS_WIDE_INTERFACE=eth0 \
    AEGIS_ENABLE_DNS_PREVIEW=1 \
    AEGIS_UDP_CAPTURE_CONTRACT=generic_capture_unstable \
    AEGIS_CLIENT_CONFIG="${config_path}" \
    bash "${ROOT}/scripts/setup-wide-linux-tproxy.sh" apply >"${output_file}" 2>&1

  PATH="${tmpdir}/bin:${PATH}" \
    AEGIS_HELPER_FIREWALL_COMMAND_LOG="${command_log}" \
    AEGIS_HELPER_FIREWALL_NFT_STATE="${nft_state}" \
    AEGIS_WIDE_FIREWALL_BACKEND=xtables \
    AEGIS_WIDE_IP_FAMILY=ipv4 \
    AEGIS_WIDE_INTERFACE=eth0 \
    AEGIS_ENABLE_DNS_PREVIEW=1 \
    AEGIS_UDP_CAPTURE_CONTRACT=generic_capture_unstable \
    AEGIS_CLIENT_CONFIG="${config_path}" \
    bash "${ROOT}/scripts/setup-wide-linux-tproxy.sh" doctor >>"${output_file}" 2>&1

  case "$(sed -n '1,260p' "${output_file}")" in
    *"Doctor result: host contract looks consistent for linux_tproxy"* ) ;;
    *)
      echo "doctor unexpectedly failed for generic contract preview drift case" >&2
      sed -n '1,260p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  case "$(sed -n '1,260p' "${output_file}")" in
    *"generic UDP capture contract is active, so dns_port / udp_preview_ports allowlist knobs are ignored"* ) ;;
    *)
      echo "missing generic-contract ignored-preview doctor note" >&2
      sed -n '1,260p' "${output_file}" >&2 || true
      rm -rf "${tmpdir}"
      exit 1
      ;;
  esac

  rm -rf "${tmpdir}"
}

python3 "${ROOT}/scripts/test-wide-linux-tproxy-doctor-contract.py"

run_case xtables ipv4 "xtables:iptables" "iptables -t mangle -N AEGIS_WIDE_TPROXY"
run_case nft ipv4 "nft" "nft add table ip aegis_wide_tproxy"
run_case xtables ipv6 "xtables:ip6tables" "ip6tables -t mangle -N AEGIS_WIDE_TPROXY"
run_case nft ipv6 "nft" "nft add table ip6 aegis_wide_tproxy"
run_case xtables ipv4 "xtables:iptables" "iptables -t mangle -N AEGIS_WIDE_TPROXY" running
run_rollout_profile_mismatch_case
run_family_mismatch_case
run_iproute2_output_variant_case
run_missing_interface_case
run_allow_all_interfaces_opt_in_case
run_policy_routing_duplicate_state_case
run_policy_routing_failure_case
run_generic_contract_ignores_preview_drift_case

echo "linux_tproxy firewall contract ok"
