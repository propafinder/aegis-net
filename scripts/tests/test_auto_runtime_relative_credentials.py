"""Real root held-FD endpoint admission with renderer-relative credentials.

Only the route observation is substituted. No actor, socket, nft or service is
created. Stages, sealed bytes, ancestors, owners, modes and descriptors are real.
"""
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

LIB = Path(__file__).resolve().parents[1] / 'lib'
sys.path.insert(0, str(LIB))
import aegis_auto_capture as capture
import aegis_auto_endpoint as endpoint


class CanonicalCredentialPaths(unittest.TestCase):
    def test_canonical_relative_and_absolute_paths(self):
        root = '/etc/aegis/client'
        for raw, expected in [('ca.pem', root + '/ca.pem'),
                              ('certs/inner.pem', root + '/certs/inner.pem'),
                              ('/var/lib/aegis-identity/client/device.key',
                               '/var/lib/aegis-identity/client/device.key')]:
            self.assertEqual(endpoint._runtime_credential_path(raw, root), expected)

    def test_alias_parent_empty_and_invalid_base_refuse(self):
        for raw in ['', '.', '..', '../ca.pem', './ca.pem', 'certs//ca.pem',
                    '/etc//ca.pem', '//etc/ca.pem', '/', 'ca.pem/', 'bad\0path', None]:
            with self.subTest(raw=raw), self.assertRaises(capture.CaptureRefused):
                endpoint._runtime_credential_path(raw, '/etc/aegis/client')
        for root in ['relative', '/', '/etc/../aegis', '/etc//aegis']:
            with self.subTest(root=root), self.assertRaises(capture.CaptureRefused):
                endpoint._runtime_credential_path('ca.pem', root)


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0,
                     'real Linux root filesystem fixture')
class RuntimeRelativeCredentials(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='aegis-endpoint-', dir='/var/lib')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / 'config'; self.config.mkdir(mode=0o700)
        self.identity = self.root / 'identity'; self.identity.mkdir(mode=0o700)
        self.stage = self.root / 'stage'; self.stage.mkdir(mode=0o700)
        self.files = {'ca': self.config / 'ca.pem', 'inner': self.config / 'inner-ca.pem',
                      'cert': self.identity / 'device.pem', 'key': self.identity / 'device.key'}
        self.material = {name: ('synthetic-' + name + '\n').encode() for name in self.files}
        for name, path in self.files.items():
            path.write_bytes(self.material[name]); path.chmod(0o600)

    def stage_write(self, name, raw):
        path = self.stage / name
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        path.write_bytes(raw); path.chmod(0o600)

    def seal(self, paths=None, missing=None):
        values = {'ca': 'ca.pem', 'inner': 'inner-ca.pem',
                  'cert': str(self.files['cert']), 'key': str(self.files['key'])}
        values.update(paths or {})
        config = ('[relay]\nserver="192.0.2.4:443"\nserver_name="relay.example"\n' +
                  'ca_cert=' + json.dumps(values['ca']) + '\n[relay.inner_tls]\n' +
                  ''.join(key + '=' + json.dumps(values[name]) + '\n' for key, name in
                          [('server_ca', 'inner'), ('cert', 'cert'), ('key', 'key')])).encode()
        path = self.config / 'aegis.toml'; path.write_bytes(config); path.chmod(0o600)
        recipe = {'schema': 2, 'context': {'mode': 'FullWideTun',
                  'logical_final_base': str(self.config)}, 'config_leaf': 'aegis.toml',
                  'config': base64.b64encode(config).decode(),
                  'references': [{'original': name, 'final_path': str(self.files[name]),
                                  'bytes': base64.b64encode(self.material[name]).decode()}
                                 for name in ['inner', 'cert', 'key'] if name != missing]}
        raw = json.dumps(recipe).encode()
        header = {'render_recipe': 'accepted/render-recipe.json',
                  'leaves': {'accepted/render-recipe.json': hashlib.sha256(raw).hexdigest()},
                  'transaction_nonce': 'n', 'planned_generation': 'g',
                  'mode': 'full-wide-tun', 'config_root': str(self.config),
                  'runtime_binding': {'identity': {'uid': 0, 'gid': 0}}}
        if missing != 'ca':
            header['leaves'][endpoint.BUNDLE_CA_LEAF] = hashlib.sha256(self.material['ca']).hexdigest()
        self.stage_write('accepted/render-recipe.json', raw)
        self.stage_write(endpoint.BUNDLE_CA_LEAF, self.material['ca'])
        self.stage_write('header.json', json.dumps(header).encode())

    @contextlib.contextmanager
    def admit(self):
        stage = os.open(self.stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            with mock.patch.object(endpoint, '_host_route', return_value={'dev': 'eth0'}):
                with endpoint.admit_runtime_endpoint(stage_fd=stage,
                        unit='aegis-auto@' + 'a' * 64 + '.service', mode='full-wide-tun',
                        transaction_nonce='n', planned_generation='g') as lease:
                    yield lease
        finally:
            os.close(stage)

    def test_existing_absolute_credentials_still_admit(self):
        self.seal({name: str(path) for name, path in self.files.items()})
        with self.admit() as lease:
            self.assertEqual([item.path for item in lease.credentials], list(self.files.values()))

    def test_renderer_relative_ca_and_external_private_key_admit(self):
        self.seal()
        with self.admit() as lease:
            self.assertEqual([item.path for item in lease.credentials], list(self.files.values()))
            self.assertEqual(lease.auth_profile, 'device_inner_tls')
            lease.revalidate()

    def test_relative_copied_private_credential_uses_exact_config_root(self):
        for name in ['cert', 'key']:
            self.files[name] = self.config / self.files[name].name
            self.files[name].write_bytes(self.material[name]); self.files[name].chmod(0o600)
        self.seal({'cert': 'device.pem', 'key': 'device.key'})
        with self.admit() as lease:
            self.assertEqual(lease.credentials[-1].path, self.files['key'])

    def test_cwd_same_name_never_substitutes_sealed_ca(self):
        other = self.root / 'cwd'; other.mkdir(mode=0o700)
        (other / 'ca.pem').write_bytes(b'wrong cwd CA')
        before = Path.cwd()
        self.seal()
        try:
            os.chdir(other)
            with self.admit() as lease:
                self.assertEqual(lease.credentials[0].sha256,
                                 hashlib.sha256(self.material['ca']).hexdigest())
        finally:
            os.chdir(before)

    def test_noncanonical_or_escaping_paths_refuse(self):
        for path in ['', '../ca.pem', './ca.pem', 'certs//ca.pem', '/',
                     str(self.config) + '/../ca.pem', '//' + str(self.files['ca']).lstrip('/')]:
            with self.subTest(path=path):
                self.seal({'ca': path})
                with self.assertRaises(capture.CaptureRefused):
                    with self.admit():
                        self.fail('unsealed path admitted')

    def test_missing_reference_and_bundle_fallback_seal_refuse(self):
        for missing in ['ca', 'inner', 'key']:
            with self.subTest(missing=missing):
                self.seal(missing=missing)
                with self.assertRaises(capture.CaptureRefused):
                    with self.admit():
                        self.fail('unsealed reference admitted')

    def test_duplicate_identical_public_reference_reuses_held_file(self):
        self.seal({'inner': 'ca.pem'})
        with self.admit() as lease:
            self.assertEqual(len(lease.credentials), 3)
            self.assertEqual(lease.credentials[0].path, self.files['ca'])

    def test_conflicting_path_alias_or_private_role_refuses(self):
        for paths in [{'inner': str(self.files['ca'])},
                      {'cert': str(self.files['key'])}]:
            with self.subTest(paths=paths):
                self.seal(paths)
                with self.assertRaises(capture.CaptureRefused):
                    with self.admit():
                        self.fail('credential alias or role conflict admitted')

    def test_live_bytes_mode_owner_links_and_alias_changes_refuse(self):
        self.seal()
        key = self.files['key']
        def refuse():
            with self.assertRaises((capture.CaptureRefused, OSError)):
                with self.admit():
                    self.fail('changed credential admitted')
        key.write_bytes(b'changed'); refuse(); key.write_bytes(self.material['key'])
        key.chmod(0o640); refuse(); key.chmod(0o600)
        os.chown(key, 501, 501); refuse(); os.chown(key, 0, 0)
        alias = self.root / 'alias'; os.link(key, alias); refuse(); alias.unlink()
        key.rename(alias); key.symlink_to(alias); refuse(); key.unlink(); alias.rename(key)
        with self.admit() as lease:
            key.rename(alias); key.write_bytes(self.material['key']); key.chmod(0o600)
            with self.assertRaises(capture.CaptureRefused):
                lease.revalidate()


if __name__ == '__main__':
    if os.environ.get('AEGIS_REQUIRE_ROOT_ENDPOINT_FIXTURE') == '1':
        assert sys.platform == 'linux' and os.geteuid() == 0, 'root fixture must execute'
    unittest.main()
