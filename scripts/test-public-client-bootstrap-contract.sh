#!/usr/bin/env bash
# Run the actual bootstrap against isolated, signed local transport fixtures.
# No server, package manager, real credential, or external network is used.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$ROOT" <<'PY'
import hashlib, io, json, os, shlex, shutil, subprocess, sys, tarfile, tempfile
from pathlib import Path
root = Path(sys.argv[1])
with tempfile.TemporaryDirectory(prefix="aegis-client-delivery-") as temp:
    work = Path(temp)
    shim = work / "commands"; shim.mkdir()
    log = work / "requests"
    # This transport records every attempted URL and serves only fixture bytes.
    (shim / "curl").write_text('''#!/usr/bin/env python3
import os, shutil, sys
from pathlib import Path
from urllib.parse import urlsplit
args=sys.argv[1:]; url=next(a for a in args if a.startswith("https://"))
with open(os.environ["FIXTURE_REQUESTS"], "a") as f: f.write(url+"\\n")
p=urlsplit(url)
if p.scheme != "https" or p.hostname not in ("primary.invalid", "mirror.invalid"):
    raise SystemExit(7)
source=Path(os.environ["FIXTURE_ROOT"])/p.hostname/p.path.lstrip("/")
if not source.is_file(): raise SystemExit(22)
shutil.copyfile(source, args[args.index("-o")+1])
''')
    (shim / "curl").chmod(0o755)
    # Observe the real verifier's key pathname before invoking OpenSSL; merely
    # checking an empty TMPDIR after cleanup would miss an unsafe transient file.
    (shim / "openssl").write_text('''#!/usr/bin/env python3
import os, sys
from pathlib import Path
args=sys.argv[1:]
if args and args[0]=="pkeyutl" and "-verify" in args:
    manifest=Path(args[args.index("-in")+1])
    key=Path(args[args.index("-inkey")+1])
    if key.parent.resolve()!=manifest.parent.resolve() or not key.name.startswith(manifest.name+".pub."):
        raise SystemExit("verification key escaped protected candidate staging")
os.execv(os.environ["FIXTURE_OPENSSL"], [os.environ["FIXTURE_OPENSSL"], *args])
''')
    (shim / "openssl").chmod(0o755)
    # On Darwin executing an env/python shebang may incur ~10s per new script.
    # A shell wrapper starts the same fixed interpreter directly (~0.4s here),
    # preserving the bounded downloader and actual fixture program unchanged.
    for name in ("curl", "openssl"):
        program=shim/(name+".py");(shim/name).rename(program)
        (shim/name).write_text("#!/bin/bash\nexec "+shlex.quote(sys.executable)+" "+shlex.quote(str(program))+' "$@"\n')
        (shim/name).chmod(0o755)
    (shim / "apt-get").write_text('#!/bin/sh\necho unexpected-package-manager >> "$FIXTURE_REQUESTS"\nexit 99\n')
    (shim / "apt-get").chmod(0o755)
    key = work / "fixture.key"; pub = work / "fixture.pub"
    def command(args): subprocess.run(args, check=True, capture_output=True)
    command(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)])
    command(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)])
    for host in ("primary.invalid", "mirror.invalid"): (work / host).mkdir()
    bootstrap = (root / "bootstrap-install.sh").read_bytes()
    # Root CI must never write the host's installation floor. Relocate only
    # the literal storage roots in this fixture copy; production has no override.
    if os.geteuid() == 0:
        bootstrap = bootstrap.replace(b"/var/lib/aegis-install/releases", str(work/"root-release-floor").encode())
        bootstrap = bootstrap.replace(b"/Library/Application Support/Aegis/Install/releases", str(work/"root-release-floor-macos").encode())
    bootstrap_script = work/"bootstrap-install.sh"; bootstrap_script.write_bytes(bootstrap)
    marker = work / "installer-ran"
    archive_name = "aegis-client-0.0.0-linux-x86_64.tar.gz"
    body = b'#!/bin/sh\nprintf "fixture-installed\\n" > "$FIXTURE_INSTALL_MARKER"\n'
    def public_archive(arch="x86_64", include_inner=True, schema="aegis_client_release_bundle_manifest_v2"):
        # Closed versioned public package shape, using inert bytes and an installer
        # marker. This exercises the signed bootstrap boundary, not native
        # client behavior or the later private access consumer.
        bundle_name = "aegis-client-0.0.0-linux-" + arch
        public = set("""bin/aegis-client install.sh config.example.toml
scripts/setup-wide-linux-redirect.sh scripts/setup-wide-linux-tproxy.sh
scripts/aegis-wide-enable.sh scripts/aegis-wide-disable.sh scripts/aegis-wide-persist-install.sh
scripts/purge-installed-aegis.sh scripts/aegis-ubuntu-uninstall.sh scripts/janitor-wide-linux-tproxy.sh
scripts/aegis-rpi-gateway.sh scripts/lib/root-state.sh packaging/systemd/aegis-client.service
packaging/env/aegis-client.env.example README.txt THIRD-PARTY-NOTICES.txt
scripts/aegis-device-egress-guard.sh""".split())
        if schema == "aegis_client_release_bundle_manifest_v1":
            public.remove("scripts/aegis-device-egress-guard.sh")
        data = {name: b"INERT_PUBLIC_FIXTURE\n" for name in public}
        data["install.sh"] = body
        data["bin/aegis-client"] = b"INERT_NOT_NATIVE_CLIENT\n"
        inner = {"schema": schema, "distribution": "public_client",
            "bundle_name": bundle_name, "version": "0.0.0", "arch": arch, "platform": "linux",
            "target_triple": arch + "-unknown-linux-gnu", "git_sha": "a" * 40,
            "build_timestamp": "2026-10-12T00:00:00Z", "cargo_lock_sha256": "b" * 64,
            "runtime_abi": {}, "binaries": {"aegis-client": {"path": "bin/aegis-client",
                "sha256": hashlib.sha256(data["bin/aegis-client"]).hexdigest(),
                "features": ["chrome-like-tls", "chrome-like-quic", "raw-socket"]}},
            "files": sorted(public | {"SHA256SUMS"}), "install_entrypoints": ["install.sh"]}
        if schema == "aegis_client_release_bundle_manifest_v3":
            # Same closed synthetic record shape as the dedicated consumer
            # fixtures. A signature authenticates these inert fixture bytes;
            # it is not evidence of an actual compiler or native linkage.
            features = ["chrome-like-quic", "chrome-like-tls", "raw-socket"]
            resolved = sorted(features + ["default"])
            identity = "c" * 64
            component_key = "aegis-client@0.0.0#" + identity
            binary_sha = inner["binaries"]["aegis-client"]["sha256"]
            inventory = {"schema": "aegis_shipping_client_cargo_inventory_v1",
                "scope": "selected_target_filtered_cargo_graph_not_compiler_linkage",
                "native_payload_complete": False, "compiler_linkage_proven": False,
                "source_revision": inner["git_sha"], "target_triple": inner["target_triple"],
                "default_features": True, "requested_features": features,
                "cargo_lock_sha256": inner["cargo_lock_sha256"], "client_binary_sha256": binary_sha,
                "cargo_metadata_sha256": "d" * 64, "root_component": component_key,
                "components": [{"key": component_key, "name": "aegis-client", "version": "0.0.0",
                    "source_kind": "reviewed_local_manifest", "source_identity_sha256": identity,
                    "features": resolved, "dependencies": []}],
                "producer": {"schema": "aegis_linux_client_build_record_v1",
                    "source_revision": inner["git_sha"], "target_triple": inner["target_triple"],
                    "cargo_lock_sha256": inner["cargo_lock_sha256"], "binary_sha256": binary_sha,
                    "default_features": True, "requested_features": features, "resolved_root_features": resolved,
                    "compiler_artifact_message_sha256": "e" * 64, "build_message_stream_sha256": "f" * 64,
                    "target_evidence": "explicit_cargo_target_and_fixed_producer_invocation"}}
            data["client-cargo-inventory.json"] = json.dumps(inventory).encode()
            public.add("client-cargo-inventory.json")
            inner["files"] = sorted(public | {"SHA256SUMS"})
        data["SHA256SUMS"] = "".join(hashlib.sha256(value).hexdigest() + "  " + name + "\n"
                                    for name, value in sorted(data.items())).encode()
        if include_inner:
            data["bundle.manifest.json"] = json.dumps(inner).encode()
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            for name, value in sorted(data.items()):
                info = tarfile.TarInfo(bundle_name + "/" + name)
                info.mode = 0o755 if name == "install.sh" else 0o644
                info.size = len(value)
                tar.addfile(info, io.BytesIO(value))
        return buffer.getvalue()
    archive = public_archive()
    manifest = {"schema":"aegis_linux_release_manifest_v1", "distribution":"public_client", "version":"0.0.0", "channel":"rc", "prerelease":True,
        "platform":"linux", "arch":"x86_64", "target_triple":"x86_64-unknown-linux-gnu", "git_sha":"a"*40,
        "artifacts":{"bundle":{"archive":{"path":archive_name,"sha256":hashlib.sha256(archive).hexdigest()}}},
        "bootstrap":{"path":"bootstrap-install.sh", "sha256":hashlib.sha256(bootstrap).hexdigest()}}
    def write_manifest(host, data, name="client-release.manifest.json"):
        path = work/host/name; path.write_text(json.dumps(data))
        command(["openssl", "pkeyutl", "-sign", "-inkey", str(key), "-rawin", "-in", str(path), "-out", str(path)+".sig"])
    for host in ("primary.invalid", "mirror.invalid"):
        write_manifest(host, manifest)
        (work/host/archive_name).write_bytes(archive)
        (work/host/"bootstrap-install.sh").write_bytes(bootstrap)
    env = {**os.environ, "HOME":str(work/"fixture-user"), "PATH":str(shim)+os.pathsep+os.environ["PATH"], "FIXTURE_ROOT":str(work), "FIXTURE_REQUESTS":str(log),
        "FIXTURE_INSTALL_MARKER":str(marker), "FIXTURE_OPENSSL":shutil.which("openssl"), "AEGIS_BOOTSTRAP_OS_KIND_OVERRIDE":"linux", "AEGIS_BOOTSTRAP_ARCH_OVERRIDE":"x86_64",
        "AEGIS_BOOTSTRAP_HOST_FAMILY_OVERRIDE":"debian_like", "AEGIS_INSTALL_MANIFEST_PUBKEY":str(pub), "AEGIS_INSTALL_PROFILE":"limited",
        "AEGIS_INSTALL_ALLOW_UNSIGNED":"0", "AEGIS_INSTALL_MIRRORS":"", "AEGIS_DOWNLOAD_CONNECT_TIMEOUT_SECONDS":"1", "AEGIS_DOWNLOAD_TOTAL_TIMEOUT_SECONDS":"2"}
    sources=["--source","https://primary.invalid/client-release.manifest.json","--source","https://mirror.invalid/client-release.manifest.json"]
    historical_manifest_pin=hashlib.sha256((work/"primary.invalid/client-release.manifest.json").read_bytes()).hexdigest()
    historical_signature_pin=hashlib.sha256((work/"primary.invalid/client-release.manifest.json.sig").read_bytes()).hexdigest()
    counter=0
    def run(args, success=True, overrides=None, script=None, historical=True):
        global counter
        counter+=1; log.write_text(""); marker.unlink(missing_ok=True)
        pins=["--allow-historical-policy","--historical-manifest-sha256",historical_manifest_pin,"--historical-signature-sha256",historical_signature_pin] if historical else []
        result=subprocess.run(["bash",str(script or bootstrap_script),"client",*pins,*args],env={**env,**(overrides or {})},capture_output=True,text=True,timeout=25)
        assert (result.returncode==0)==success,(args,result.stdout,result.stderr)
        assert "github.com" not in log.read_text(), "explicit sources contacted GitHub"
        assert "unexpected-package-manager" not in log.read_text()
        return result
    # The explicitly configured public anchor is authority, not an untrusted
    # transport file. Reject unsafe mode, link, or absent path before install.
    unsafe_pub=work/"unsafe-anchor.pub";shutil.copyfile(pub,unsafe_pub);unsafe_pub.chmod(0o666)
    linked_pub=work/"linked-anchor.pub";linked_pub.symlink_to(pub)
    for keypath in (unsafe_pub, linked_pub, work/"missing-anchor.pub"):
        run(sources,False,{"AEGIS_INSTALL_MANIFEST_PUBKEY":str(keypath)})
        assert not marker.exists()
    # A genuinely signed public archive missing inner provenance must not
    # execute its installer. Refresh historical pins for this exact signed
    # negative candidate, then restore the positive release unchanged.
    saved_pins = historical_manifest_pin, historical_signature_pin
    omitted = json.loads(json.dumps(manifest))
    missing_inner_archive = public_archive(include_inner=False)
    omitted["artifacts"]["bundle"]["archive"]["sha256"] = hashlib.sha256(missing_inner_archive).hexdigest()
    for host in ("primary.invalid", "mirror.invalid"):
        write_manifest(host, omitted)
        (work / host / archive_name).write_bytes(missing_inner_archive)
    historical_manifest_pin = hashlib.sha256((work/"primary.invalid/client-release.manifest.json").read_bytes()).hexdigest()
    historical_signature_pin = hashlib.sha256((work/"primary.invalid/client-release.manifest.json.sig").read_bytes()).hexdigest()
    missing_inner_result = run(sources, False); assert not marker.exists()
    assert "verified release inner provenance missing" in missing_inner_result.stderr
    for host in ("primary.invalid", "mirror.invalid"):
        write_manifest(host, manifest)
        (work / host / archive_name).write_bytes(archive)
    historical_manifest_pin, historical_signature_pin = saved_pins
    def signed_archive_positive(candidate_archive, public=True):
        global historical_manifest_pin, historical_signature_pin
        saved_pins = historical_manifest_pin, historical_signature_pin
        candidate_manifest = json.loads(json.dumps(manifest))
        if not public:
            candidate_manifest.pop("distribution")
        candidate_manifest["artifacts"]["bundle"]["archive"]["sha256"] = hashlib.sha256(candidate_archive).hexdigest()
        for host in ("primary.invalid", "mirror.invalid"):
            write_manifest(host, candidate_manifest)
            (work / host / archive_name).write_bytes(candidate_archive)
        historical_manifest_pin = hashlib.sha256((work/"primary.invalid/client-release.manifest.json").read_bytes()).hexdigest()
        historical_signature_pin = hashlib.sha256((work/"primary.invalid/client-release.manifest.json.sig").read_bytes()).hexdigest()
        run(sources); assert marker.exists()
        for host in ("primary.invalid", "mirror.invalid"):
            write_manifest(host, manifest)
            (work / host / archive_name).write_bytes(archive)
        historical_manifest_pin, historical_signature_pin = saved_pins

    # Execute only the existing inert installer marker after real signature,
    # freshness/historical pins, archive digest and versioned admission checks.
    signed_archive_positive(public_archive(schema="aegis_client_release_bundle_manifest_v1"))
    signed_archive_positive(public_archive(schema="aegis_client_release_bundle_manifest_v3"))
    source_buffer = io.BytesIO()
    with tarfile.open(fileobj=source_buffer, mode="w:gz") as tar:
        for name in ("aegis-client", "aegis-server"):
            info = tarfile.TarInfo("aegis-source-fixture/" + name)
            info.type = tarfile.DIRTYPE; info.mode = 0o755
            tar.addfile(info)
        for name, value in (("install.sh", body), ("Cargo.toml", b"INERT_SOURCE_LAYOUT_MARKER\n")):
            info = tarfile.TarInfo("aegis-source-fixture/" + name)
            info.mode = 0o755 if name == "install.sh" else 0o644; info.size = len(value)
            tar.addfile(info, io.BytesIO(value))
    signed_archive_positive(source_buffer.getvalue(), public=False)
    # Whole primary unavailable: signed mirror selected.
    first=work/"primary.invalid/client-release.manifest.json"; first.rename(first.with_suffix(".saved"))
    run(sources); assert marker.exists()
    first.with_suffix(".saved").rename(first)
    # Valid primary metadata, unavailable archive: same digest via mirror.
    (work/"primary.invalid"/archive_name).unlink()
    run(sources); assert marker.exists() and "mirror.invalid/"+archive_name in log.read_text()
    # Primary archive corrupt: continue, but retain the primary signed hash.
    (work/"primary.invalid"/archive_name).write_bytes(b"different inert fixture")
    run(sources); assert marker.exists()
    (work/"mirror.invalid"/archive_name).write_bytes(b"also different inert fixture")
    changed=json.loads(json.dumps(manifest)); changed["artifacts"]["bundle"]["archive"]["sha256"]=hashlib.sha256(b"also different inert fixture").hexdigest()
    write_manifest("mirror.invalid", changed)
    run(sources, False); assert not marker.exists(), "alternate manifest changed selected release identity"
    (work/"mirror.invalid"/archive_name).write_bytes(archive); write_manifest("mirror.invalid", manifest)
    # Download-only must retain a reusable kit and never request a private bundle.
    kit=work/"kit"
    private_access=work/"private-access.txt"
    private_access.write_text("https://private.invalid/one-time");private_access.chmod(0o600)
    run([*sources,"--download-only","--download-dir",str(kit),"--bundle-url-file",str(private_access)])
    assert not marker.exists() and "private.invalid" not in log.read_text()
    assert (kit/archive_name).read_bytes()==archive
    assert (kit/"bootstrap-install.sh").read_bytes()==bootstrap
    run(["--offline","--source",(kit/"release.manifest.json").as_uri(),"--bundle",str(work/"inert-access-fixture")],script=kit/"bootstrap-install.sh")
    assert marker.exists() and not log.read_text(), "offline kit used network transport"
    run(["--offline",*sources], False); assert not log.read_text() and not marker.exists()
    # This inert public-stage installer cannot validate the later private Rust
    # consumer. Here prove forwarding/local-only admission instruction only;
    # actual private rejection belongs to the dedicated transport contract.
    run(["--offline","--source",(kit/"release.manifest.json").as_uri(),"--bundle-url-file",str(private_access)])
    assert not log.read_text() and marker.exists()
    run(["--offline",*sources], False, {"AEGIS_BOOTSTRAP_SIMULATE_MISSING_COMMANDS":"openssl"})
    assert not log.read_text()
    # Public client metadata rejects the wrong CPU before archive/install.
    run(sources, False, {"AEGIS_BOOTSTRAP_ARCH_OVERRIDE":"s390x"}); assert not marker.exists()
    arm=json.loads(json.dumps(manifest));arm.update(arch="aarch64", target_triple="aarch64-unknown-linux-gnu")
    arm_archive_name = "aegis-client-0.0.0-linux-aarch64.tar.gz"
    arm_archive = public_archive("aarch64")
    arm["artifacts"]["bundle"]["archive"].update(path=arm_archive_name, sha256=hashlib.sha256(arm_archive).hexdigest())
    write_manifest("primary.invalid", arm, "client-release.manifest-aarch64.json")
    (work/"primary.invalid"/arm_archive_name).write_bytes(arm_archive)
    historical_manifest_pin=hashlib.sha256((work/"primary.invalid/client-release.manifest-aarch64.json").read_bytes()).hexdigest()
    historical_signature_pin=hashlib.sha256((work/"primary.invalid/client-release.manifest-aarch64.json.sig").read_bytes()).hexdigest()
    run(sources, overrides={"AEGIS_BOOTSTRAP_ARCH_OVERRIDE":"aarch64"})
    assert "client-release.manifest-aarch64.json" in log.read_text() and marker.exists()
    # An unsafe TMPDIR is skipped for staging and must never be used again
    # for the pinned verification-key temporary pathname.
    unsafe_tmp=work/"unsafe-tmp";unsafe_tmp.mkdir();unsafe_tmp.chmod(0o777)
    before=set(unsafe_tmp.iterdir())
    run(sources, overrides={"TMPDIR":str(unsafe_tmp),"AEGIS_BOOTSTRAP_ARCH_OVERRIDE":"aarch64"})
    assert marker.exists() and set(unsafe_tmp.iterdir())==before
    # Freshness is checked on each verified candidate before archive requests,
    # so an expired signed primary may fall back to a current signed mirror.
    import time, copy
    now=int(time.time())
    authority="github:fixture-owner/fixture-repo:.github/workflows/release.yml"
    policy={"schema":"aegis_release_policy_v1","authority":authority,"sequence":123,
        "tag":"v0.0.0-rc.1","issued_at_unix":now-5,"expires_at_unix":now+3600}
    fresh={**manifest,"release_policy":policy}
    expired=copy.deepcopy(fresh);expired["release_policy"]["issued_at_unix"]=now-3600;expired["release_policy"]["expires_at_unix"]=now-1
    write_manifest("primary.invalid",expired);write_manifest("mirror.invalid",fresh)
    run([*sources,"--require-release-policy"]);assert marker.exists()
    assert "mirror.invalid/client-release.manifest.json" in log.read_text()
    write_manifest("primary.invalid",fresh)
    run([*sources,"--minimum-release-sequence","123","--release-authority",authority]);assert marker.exists()
    for options in (["--minimum-release-sequence","124","--release-authority",authority],
                    ["--minimum-release-sequence","123"],
                    ["--release-authority","github:other/repo:.github/workflows/release.yml"]):
        run([*sources,*options],False);assert not marker.exists()
    for field,value in [("tag","v9.9.9"),("sequence",True),("expires_at_unix",now+31*86400),("issued_at_unix",now+600)]:
        invalid=copy.deepcopy(fresh);invalid["release_policy"][field]=value
        for host in ("primary.invalid","mirror.invalid"):write_manifest(host,invalid)
        run([*sources,"--require-release-policy"],False);assert not marker.exists()
    for host in ("primary.invalid","mirror.invalid"):write_manifest(host,manifest)
    run([*sources,"--require-release-policy"],False);assert not marker.exists()
    run(sources,False,historical=False);assert not marker.exists(), "missing policy accepted by default"
    # A service-writable staging parent or pre-existing link can replace the
    # verified extracted installer; reject before any transport operation.
    private_dir=work/'private-stage';private_dir.mkdir(mode=0o700)
    stage_link=work/'stage-link';stage_link.symlink_to(private_dir)
    run([*sources,'--download-dir',str(stage_link)],False,historical=False)
    assert not log.read_text() and not marker.exists()
    writable_parent=work/'writable-parent';writable_parent.mkdir();writable_parent.chmod(0o777)
    run([*sources,'--download-dir',str(writable_parent/'child')],False,historical=False)
    assert not log.read_text() and not marker.exists() and not (writable_parent/'child').exists()
    linked_file=private_dir/'existing';os.link(work/'primary.invalid/client-release.manifest.json',linked_file)
    run([*sources,'--download-dir',str(private_dir)],False,historical=False)
    assert not log.read_text() and not marker.exists()
    # Installer output delegates to the shared Rust renderer. Its independent
    # pin checks and inert execution fixtures live in bootstrap_launcher/tests.
    import re
    renderer=re.search(r'^print_client_bootstrap_command\(\) \{\n.*?^\}',(root/"install.sh").read_text(),re.M|re.S)[0]
    renderer_stub=work/"renderer-stub"
    renderer_stub.write_text('#!/bin/bash\nprintf "%s\\n" "$@"\n'); renderer_stub.chmod(0o755)
    invocation=renderer+'\nprint_client_bootstrap_command "$FIXTURE_PRIVATE_ACCESS" "$FIXTURE_RENDERER"'
    onboarding_env={**env,"AEGIS_CLIENT_LAUNCHER_PINS":"/trusted/fixture-pins.json","FIXTURE_RENDERER":str(renderer_stub),"FIXTURE_PRIVATE_ACCESS":str(private_access)}
    rendered=subprocess.run(["bash","-c",invocation],env=onboarding_env,capture_output=True,text=True,check=True).stdout
    assert rendered.splitlines()==["install-launcher","--pins","/trusted/fixture-pins.json","--bundle-url-file",str(private_access)]
    rejected=subprocess.run(["bash","-c",invocation],env={**onboarding_env,"AEGIS_CLIENT_LAUNCHER_PINS":""},capture_output=True,text=True)
    assert rejected.returncode!=0 and not rejected.stdout
    counter+=2
    print(f"PASS: {counter} public client bootstrap scenarios; explicit mirrors, fixed signed digest, architecture, reusable offline kit, zero secret consumption")
PY
