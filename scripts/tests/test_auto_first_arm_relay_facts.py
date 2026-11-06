"""Run the actual first-arm input program with real protected files and flock."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import sys
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[2] / 'install.sh'
PROGRAM = SOURCE.read_text().split("<<'PY_AUTO_GUARD_INPUT'\n", 1)[1].split('\nPY_AUTO_GUARD_INPUT', 1)[0]


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0,
                     'real Linux root flock admission')
class FirstArmRelayFactsTests(unittest.TestCase):
    def run_input(self, primary, others, answers):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, output = root / 'input.toml', root / 'facts.json'
            text = 'mode="relay"\n[relay]\nserver=' + json.dumps(primary) + '\n'
            text += ''.join('[[relay.endpoints]]\nserver=' + json.dumps(value) + '\n' for value in others)
            config.write_text(text)
            config.chmod(0o600)
            lock = os.open(root / 'lock', os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            original_stat = os.stat
            # Only the fixed lock pathname is redirected to the real held
            # fixture inode. Production fdinfo parsing and flock stay actual.
            def named(path, **kwargs):
                return original_stat(root / 'lock' if path == '/run/aegis-auto-install.lock' else path, **kwargs)
            previous = signal.getsignal(signal.SIGALRM)
            try:
                rows = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (address, 443)) for address in answers]
                with mock.patch.object(sys, 'argv', ['first-arm', str(config), str(lock), str(output)]), \
                     mock.patch.object(os, 'stat', side_effect=named), \
                     mock.patch.object(socket, 'getaddrinfo', return_value=rows) as dns:
                    failure = None
                    try:
                        exec(compile(PROGRAM, str(SOURCE) + ':first-arm', 'exec'), {})
                    except SystemExit as error:
                        failure = str(error)
                    result = json.loads(output.read_bytes()) if output.exists() else None
                    return failure, result, dns.call_count, hashlib.sha256(config.read_bytes()).hexdigest()
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, previous)
                os.close(lock)

    def test_repeated_primary_hostname_uses_one_resolution(self):
        failure, result, calls, config_sha = self.run_input('primary.test:443', ['primary.test:443'], ['203.0.113.10'])
        self.assertIsNone(failure)
        self.assertEqual(calls, 1)
        self.assertEqual(result['relay_servers'], ['203.0.113.10:443'])
        self.assertEqual(result['relay_endpoints'], [])
        self.assertEqual(result['source_config_sha256'], config_sha)

    def test_distinct_secondary_hostname_still_refuses(self):
        failure, result, calls, _ = self.run_input('primary.test:443', ['other.test:443'], ['203.0.113.10'])
        self.assertIsNotNone(failure)
        self.assertIsNone(result)
        self.assertEqual(calls, 1)

    def test_numeric_endpoints_and_duplicates_need_no_dns(self):
        failure, result, calls, _ = self.run_input('203.0.113.10:443', ['203.0.113.10:443', '203.0.113.11:2442'], [])
        self.assertIsNone(failure)
        self.assertEqual(calls, 0)
        self.assertEqual(result['relay_servers'], ['203.0.113.10:443', '203.0.113.11:2442'])

    def test_multiple_primary_addresses_still_refuse(self):
        failure, result, calls, _ = self.run_input('primary.test:443', ['primary.test:443'], ['203.0.113.10', '203.0.113.11'])
        self.assertIsNotNone(failure)
        self.assertIsNone(result)
        self.assertEqual(calls, 1)


if __name__ == '__main__':
    unittest.main()
