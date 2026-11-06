#!/usr/bin/env bash
# Run real prerequisite selection/orchestration with inert package commands.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
python3 - "$ROOT" <<'PY'
import pathlib,re,subprocess,sys,tempfile
s=(pathlib.Path(sys.argv[1])/'bootstrap-install.sh').read_text()
names=['append_unique_word','automatic_client_requested','bootstrap_prereq_packages','install_debian_like_prereqs','install_rhel_like_prereqs','ensure_bootstrap_prereqs']
functions='\n'.join(re.search(r'^'+n+r'\(\) \{\n.*?^\}',s,re.M|re.S)[0] for n in names)
with tempfile.TemporaryDirectory(prefix='aegis-bootstrap-prereq-') as tmp:
 log=pathlib.Path(tmp)/'calls'
 base='''set -euo pipefail
ROLE=client
FORWARDED_ARGS=()
APT_GET_BIN=apt-get
DNF_BIN=dnf
OFFLINE=0
DOWNLOAD_ONLY=0
MISSING=ip,iptables,ip6tables,nft,flock,getent
has_ca_certificates(){ return 0; }
prereq_has_command(){ case ",$MISSING," in *",$1,"*) return 1;; *) return 0;; esac; }
has_command(){ [[ "${NO_MANAGER:-0}" == 0 ]]; }
run_as_root(){ printf '%s\\n' "$*" >> '''+repr(str(log))+'''; }
'''+functions+'\n'
 def check(label,setup='',family='rhel_like',ok=True,expected=()):
  log.unlink(missing_ok=True)
  r=subprocess.run(['bash','-c',base+setup+'\nensure_bootstrap_prereqs '+family],text=True,capture_output=True)
  assert (r.returncode==0)==ok,(label,r.stdout,r.stderr)
  calls=log.read_text().splitlines() if log.exists() else []
  assert calls==list(expected),(label,calls,expected)
  print('PASS:',label)
 check('RHEL9 signed prerequisites',expected=['dnf --setopt=gpgcheck=1 --setopt=*.gpgcheck=1 --setopt=localpkg_gpgcheck=1 install -y iproute iptables-nft nftables util-linux glibc-common'])
 check('Debian complete guard dependencies',family='debian_like',expected=['apt-get update','apt-get install -y iproute2 iptables nftables util-linux libc-bin'])
 check('already installed is no-op','MISSING=')
 check('server does not install client networking','ROLE=server')
 check('explicit SOCKS profile avoids networking packages','FORWARDED_ARGS=(--profile socks-only)')
 check('offline missing dependencies never calls manager','OFFLINE=1',ok=False)
 check('download-only needs no client networking','DOWNLOAD_ONLY=1')
 check('offline complete dependencies is no-op','OFFLINE=1; MISSING=')
 check('missing dnf fails without fallback','NO_MANAGER=1',ok=False)
 check('unsupported family remains explicit',family='generic_linux',ok=False)
 check('download-only lacks crypto verifier','DOWNLOAD_ONLY=1; MISSING=openssl',ok=False)
 print('PASS:11 bootstrap prerequisite scenarios; no real package/network commands')
PY
