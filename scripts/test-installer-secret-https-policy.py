#!/usr/bin/env python3
"""Actual private fetch CLI and loopback HTTP/TLS; QA only, no public network."""
import argparse
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time

class Invalid(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def private(path, value):
    data = value.encode() if isinstance(value, str) else value
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(data)

def record(path, value):
    private(path, json.dumps(value, indent=2) + '\n')

def run(work, label, argv, env, bound=130):
    case = work / label
    case.mkdir(mode=0o700)
    output, errors = case / 'stdout.log', case / 'stderr.log'
    deadline = time.monotonic() + bound
    child = None
    observed, issue, status = False, None, None
    attempted = []
    with output.open('xb') as stdout, errors.open('xb') as stderr:
        output.chmod(0o600)
        errors.chmod(0o600)
        try:
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout,
                                     stderr=stderr, env=env, start_new_session=True)
            record(case / 'owned-start.json', {'pid': child.pid, 'bound_seconds': bound})
            while time.monotonic() < deadline:
                if os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT):
                    observed = True
                    break
                time.sleep(0.005)
            if not observed:
                issue = 'command_deadline'
        except BaseException as failure:
            issue = type(failure).__name__
        finally:
            if child is not None:
                cleanup = time.monotonic() + 4
                # Retain the leader with WNOWAIT until both owned group signals.
                for value in (signal.SIGTERM, signal.SIGKILL):
                    try:
                        os.killpg(child.pid, value)
                        attempted.append(int(value))
                    except ProcessLookupError:
                        pass
                    except PermissionError:
                        # An observed Darwin singleton zombie can refuse signals;
                        # this does not prove the absence of other descendants.
                        if not observed:
                            issue = issue or 'group_signal_unconfirmed'
                while time.monotonic() < cleanup:
                    status = child.poll()
                    if status is not None:
                        break
                    time.sleep(0.005)
            record(case / 'execution.json', {
                'pid': child.pid if child is not None else None,
                'exit_code': status, 'observed_before_cleanup': observed,
                'leader_reaped': status is not None, 'problem': issue,
                'group_signal_attempts': attempted,
                'stdout_sha256': digest(output), 'stderr_sha256': digest(errors),
                'descendant_scope': 'owned group; independent outer supervisor required',
            })
    if not observed or status is None or issue is not None:
        raise Invalid('owned_command_unconfirmed')
    return status, output.read_bytes() + errors.read_bytes()

class FixtureServer(http.server.ThreadingHTTPServer):
    daemon_threads = False
    block_on_close = False
    allow_reuse_address = False
    def get_request(self):
        peer, address = self.socket.accept()
        peer.settimeout(1)
        if self.owner.context is not None:
            try:
                peer = self.owner.context.wrap_socket(peer, server_side=True)
            except BaseException:
                peer.close()
                raise
        with self.owner.lock:
            self.owner.connections.append(peer)
        return peer, address
    def process_request(self, request, address):
        thread = threading.Thread(target=self.process_request_thread,
                                  args=(request, address), daemon=False)
        with self.owner.lock:
            self.owner.children.append(thread)
        thread.start()

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass
    def do_GET(self):
        owner = self.server.owner
        with owner.lock:
            owner.events.append(self.path)
        if self.path.startswith('/redirect?'):
            self.send_response(302)
            self.send_header('Location', owner.redirect_base + self.path.split('?', 1)[1])
            self.send_header('Content-Length', '0')
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header('Content-Length', str(len(owner.payload)))
            self.end_headers()
            self.wfile.write(owner.payload)

class Endpoint:
    def __init__(self, payload, context=None):
        self.context, self.payload = context, payload
        self.lock = threading.Lock()
        self.events, self.children, self.connections = [], [], []
        self.stop = threading.Event()
        self.redirect_base = None
        self.server = FixtureServer(('127.0.0.1', 0), Handler)
        self.server.owner = self
        self.server.timeout = 0.1
        self.thread = threading.Thread(target=self.serve, daemon=False)
        self.thread.start()
    @property
    def port(self):
        return self.server.server_address[1]
    def serve(self):
        while not self.stop.is_set():
            try:
                self.server.handle_request()
            except (OSError, ValueError):
                if self.stop.is_set():
                    return
    def count(self, canary):
        with self.lock:
            return sum(canary in value for value in self.events)
    def close(self):
        deadline = time.monotonic() + 2
        self.stop.set()
        self.server.server_close()
        # Stop/join the accepting owner before freezing the complete handler list.
        # A handler cannot be appended after this successful serving-owner join.
        self.thread.join(max(0, deadline - time.monotonic()))
        serving_stopped = not self.thread.is_alive()
        with self.lock:
            connections = list(self.connections)
            children = list(self.children)
        for peer in connections:
            try:
                peer.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            peer.close()
        for thread in [self.thread] + children:
            thread.join(max(0, deadline - time.monotonic()))
        if not serving_stopped or any(thread.is_alive() for thread in [self.thread] + children):
            raise Invalid('endpoint_cleanup_unconfirmed')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--client', required=True)
    parser.add_argument('--receipt-dir')
    parser.add_argument('--role', choices=['baseline', 'candidate'], default='candidate')
    args = parser.parse_args()
    work = Path(args.receipt_dir).absolute() if args.receipt_dir else Path(
        tempfile.mkdtemp(prefix='aegis-private-https-policy-')).resolve()
    if args.receipt_dir:
        work.mkdir(mode=0o700, exist_ok=False)
    work.chmod(0o700)
    rows, endpoints = [], []
    try:
        if not hasattr(os, 'waitid') or not hasattr(os, 'WNOWAIT'):
            raise Invalid('owned_wait_observation_unavailable')
        client = Path(args.client).resolve()
        curl, openssl = shutil.which('curl'), shutil.which('openssl')
        if not client.is_file() or not os.access(client, os.X_OK) or not curl or not openssl:
            raise Invalid('actual_client_curl_openssl_required')
        original_pin = digest(client)
        binary = work / 'aegis-client'
        shutil.copyfile(client, binary)
        binary.chmod(0o700)
        if digest(binary) != original_pin or digest(client) != original_pin:
            raise Invalid('binary_copy_race')
        tools = work / 'actual-tools'
        tools.mkdir(mode=0o700)
        (tools / 'curl').symlink_to(Path(curl).resolve())
        home = work / 'owned-home'
        home.mkdir(mode=0o700)
        env = {'PATH': str(tools), 'HOME': str(home), 'TMPDIR': str(work), 'LANG': 'C'}
        record(work / 'pins.json', {'client_sha256': original_pin,
               'curl_sha256': digest(Path(curl).resolve()),
               'openssl_sha256': digest(Path(openssl).resolve()), 'role': args.role})
        cert, key, config = work / 'cert.pem', work / 'key.pem', work / 'openssl.cnf'
        private(config, '[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n'
                '[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n'
                'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n')
        rc, _ = run(work, 'certificate', [openssl, 'req', '-x509', '-newkey', 'rsa:2048',
                    '-sha256', '-nodes', '-days', '1', '-keyout', str(key),
                    '-out', str(cert), '-config', str(config)], env, bound=20)
        if rc != 0 or not cert.is_file() or not key.is_file():
            raise Invalid('certificate_generation_failed')
        cert.chmod(0o600)
        key.chmod(0o600)
        rc, _ = run(work, 'public-key', [openssl, 'x509', '-in', str(cert),
                    '-pubkey', '-noout'], env, bound=20)
        if rc != 0:
            raise Invalid('certificate_public_key_failed')
        pub = work / 'public-key/stdout.log'
        rc, _ = run(work, 'public-der', [openssl, 'pkey', '-pubin', '-in', str(pub),
                    '-outform', 'DER'], env, bound=20)
        if rc != 0:
            raise Invalid('public_key_der_failed')
        spki = 'sha256//' + base64.b64encode(hashlib.sha256(
            (work / 'public-der/stdout.log').read_bytes()).digest()).decode('ascii')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        payload = b'AEGIS audit77 actual loopback bundle bytes\n'
        http = Endpoint(payload)
        endpoints.append(http)
        https = Endpoint(payload, context)
        endpoints.append(https)
        https.redirect_base = f'http://127.0.0.1:{http.port}/bundle?'
        local = work / 'local.bundle'
        private(local, payload)
        def one(name, mode, flags=(), trust=False):
            case = work / ('data-' + name)
            case.mkdir(mode=0o700)
            canary = 'AUDIT77_SYNTHETIC_' + name.replace('-', '_')
            if mode == 'http':
                url = f'http://127.0.0.1:{http.port}/bundle?token={canary}'
            elif mode == 'redirect':
                url = f'https://127.0.0.1:{https.port}/redirect?token={canary}'
            elif mode == 'https':
                url = f'https://127.0.0.1:{https.port}/bundle?token={canary}'
            elif mode == 'file':
                url = local.as_uri()
            else:
                url = str(local)
            access, output = case / 'access', case / 'output'
            private(access, url)
            command_env = dict(env)
            if name == 'implicit-insecure-config':
                owned_home = case / 'curl-home'
                owned_home.mkdir(mode=0o700)
                private(owned_home / '.curlrc', 'insecure\n')
                command_env['HOME'] = str(owned_home)
            if trust:
                command_env['CURL_CA_BUNDLE'] = str(cert)
            rc, diagnostic = run(work, 'command-' + name,
                [str(binary), 'profile', 'installer-secret', 'fetch', '--input', str(access),
                 '--output', str(output), '--connect-seconds', '10', '--total-seconds', '120']
                + list(flags), command_env)
            h, s = http.count(canary), https.count(canary)
            transferred = rc == 0 and output.is_file() and output.read_bytes() == payload
            if url.encode() in diagnostic:
                raise Invalid('private_url_in_diagnostic')
            if mode == 'http':
                refused = rc == 2 and b'reason=unsupported_url_scheme' in diagnostic and not output.exists() and h == s == 0
                valid = (transferred and h == 1 and s == 0) or refused
                passed = refused
            elif mode == 'redirect':
                valid = s == 1 and ((transferred and h == 1) or (rc != 0 and h == 0 and not output.exists()))
                passed = valid and h == 0 and rc != 0 and not output.exists()
            elif name == 'unpinned-insecure':
                refused = rc == 2 and b'reason=unpinned_insecure_refused' in diagnostic and not output.exists() and h == s == 0
                valid = (transferred and s == 1 and h == 0) or refused
                passed = refused
            elif name == 'implicit-insecure-config':
                refused = rc == 60 and b'reason=failed' in diagnostic and not output.exists() and h == s == 0
                valid = (transferred and s == 1 and h == 0) or refused
                passed = refused
            elif name == 'wrong-spki':
                # Actual known-good pin success below is a separate prerequisite;
                # exit90 is curl's real SPKI-mismatch refusal, before any HTTP GET.
                valid = rc == 90 and b'reason=failed' in diagnostic and not output.exists() and h == s == 0
                passed = valid
            else:
                valid = transferred and h == 0 and s == (1 if mode == 'https' else 0)
                passed = valid
            rows.append({'case': name, 'result': 'PASS' if passed else ('FAIL' if valid else 'INVALID'),
                         'actual_precondition_valid': valid, 'exit_code': rc,
                         'http_canary_requests': h, 'https_canary_requests': s,
                         'exact_payload_published': transferred, 'output_exists': output.exists()})
            print(f'audit77 case={name} result={rows[-1]["result"]} http={h} https={s}', flush=True)
        one('http-initial', 'http')
        one('https-downgrade', 'redirect', trust=True)
        one('unpinned-insecure', 'https', ['--insecure'])
        one('implicit-insecure-config', 'https')
        one('trusted-https', 'https', trust=True)
        one('pinned-https', 'https', ['--pin', spki])
        if rows[-1]['result'] != 'PASS':
            raise Invalid('good_spki_positive_required')
        wrong_spki = 'sha256//' + base64.b64encode(bytes(32)).decode('ascii')
        if wrong_spki == spki:
            raise Invalid('distinct_wrong_spki_required')
        one('wrong-spki', 'https', ['--pin', wrong_spki])
        one('offline-file', 'file', ['--local-only'])
        if digest(client) != original_pin or digest(binary) != original_pin:
            raise Invalid('binary_changed_after_cases')
    except BaseException as failure:
        rows.append({'case': 'fixture-admission', 'result': 'INVALID',
                     'kind': type(failure).__name__,
                     'reason': failure.code if isinstance(failure, Invalid) else 'unexpected_exception'})
    finally:
        cleanup_ok = True
        for endpoint in reversed(endpoints):
            try:
                endpoint.close()
            except BaseException:
                cleanup_ok = False
        if not cleanup_ok:
            rows.append({'case': 'endpoint-cleanup', 'result': 'INVALID'})
    counts = {key: sum(row['result'] == key for row in rows) for key in ('PASS', 'FAIL', 'INVALID')}
    record(work / 'final.json', {'role': args.role, 'rows': rows, 'counts': counts,
           'endpoint_cleanup_confirmed': cleanup_ok,
           'source_or_native_platform_acceptance': False,
           'scope': 'actual compiled Unix CLI plus actual curl and controlled loopback endpoints',
           'wget_runtime_measured': False,
           'outer_supervisor_required': True})
    print(f'audit77 fixture complete cases={len(rows)} pass={counts["PASS"]} fail={counts["FAIL"]} invalid={counts["INVALID"]}', flush=True)
    print('audit77 receipt_dir=' + str(work), flush=True)
    return 2 if counts['INVALID'] else (1 if counts['FAIL'] else 0)

if __name__ == '__main__':
    raise SystemExit(main())
