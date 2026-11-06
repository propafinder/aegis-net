#!/usr/bin/env python3
"""License-source confinement canaries; Cargo and real user data are not read."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location('notices',
    Path(__file__).with_name('generate-third-party-notices.py'))
notices=importlib.util.module_from_spec(spec);spec.loader.exec_module(notices)


class SourceCustody(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name).resolve();self.package=self.root/'crate';self.package.mkdir()
        (self.package/'Cargo.toml').write_text('[package]\nname="fixture"\n')
        self.private=self.root/'private-canary';self.private.write_text('PRIVATE_CANARY_MUST_NOT_BE_EMBEDDED\n')
        self.public=b'Public fixture license\n';(self.package/'LICENSE').write_bytes(self.public)
        self.explicit=None
        def scope(entries,*_args,metadata_superset=False):
            entries[('fixture','1.0.0','registry+fixture')]={'package':{
                'manifest_path':str(self.package/'Cargo.toml'),'license':'MIT',
                'license_file':self.explicit},'scopes':{'fixture'}}
        patch=mock.patch.object(notices,'add_scope',side_effect=scope);patch.start();self.addCleanup(patch.stop)

    def test_public_relative_and_absolute_in_package_licenses_are_stable(self):
        baseline=notices.render()
        for value in ('LICENSE',str(self.package/'LICENSE')):
            self.explicit=value
            self.assertEqual(notices.render(),baseline)
        self.assertIn(self.public.decode(),baseline)
        self.assertNotIn('PRIVATE_CANARY_MUST_NOT_BE_EMBEDDED',baseline)

    def test_explicit_parent_and_absolute_escape_never_embed_private_bytes(self):
        for value in ('../private-canary',str(self.private)):
            self.explicit=value
            with self.subTest(value=value),self.assertRaises((ValueError,RuntimeError)):
                notices.render()

    def test_explicit_directory_symlink_cannot_escape_package(self):
        (self.package/'linked').symlink_to(self.root,target_is_directory=True)
        self.explicit='linked/private-canary'
        with self.assertRaises((ValueError,RuntimeError)):notices.render()

    def test_implicit_license_alias_and_hardlink_are_refused(self):
        license=self.package/'LICENSE';license.unlink();license.symlink_to(self.private)
        with self.assertRaises((ValueError,RuntimeError)):notices.render()
        license.unlink();os.link(self.private,license)
        with self.assertRaises((ValueError,RuntimeError)):notices.render()

    def test_leaf_replacement_while_reading_is_refused(self):
        original=os.read;changed=False
        def read(fd,size):
            nonlocal changed
            if not changed:
                changed=True;(self.package/'LICENSE').rename(self.package/'old-license')
                (self.package/'LICENSE').write_bytes(self.public)
            return original(fd,size)
        with mock.patch.object(os,'read',side_effect=read):
            with self.assertRaises((ValueError,RuntimeError)):notices.render()

    def test_package_ancestor_replacement_with_identical_bytes_is_refused(self):
        original=os.read;changed=False
        def read(fd,size):
            nonlocal changed
            if not changed:
                changed=True;self.package.rename(self.root/'held-old-crate');self.package.mkdir()
                (self.package/'LICENSE').write_bytes(self.public)
            return original(fd,size)
        with mock.patch.object(os,'read',side_effect=read):
            with self.assertRaises((ValueError,RuntimeError)):notices.render()


if __name__=='__main__':unittest.main()
