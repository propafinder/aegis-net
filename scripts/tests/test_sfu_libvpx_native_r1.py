#!/usr/bin/env python3
"""Source/archive controls for the optional native SFU build recipe."""

import io
from pathlib import Path
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "qa/sfu-libvpx-native-r1.py"
scope = {"__name__": "sfu_libvpx_recipe_test"}
exec(compile(SCRIPT.read_bytes(), str(SCRIPT), "exec"), scope)


class NativeSourceControls(unittest.TestCase):
    def test_exact_upstream_identity(self):
        self.assertEqual(scope["TAG"], "v1.17.0")
        self.assertEqual(scope["COMMIT"], "6df3ec34557879fff673706f4a1d9fbd0f3a6f0e")
        self.assertEqual(scope["TREE"], "f83d33a1ba18b3a203e43596b5223042b62417a3")
        self.assertEqual(scope["REQUIRED_LINK_SYMBOLS"], {
            "_vpx_codec_vp8_cx", "_vpx_codec_vp8_dx",
            "_vpx_codec_vp9_cx", "_vpx_codec_vp9_dx",
        })

    def test_archive_rejects_traversal_and_symlink_escape(self):
        for name, kind, link in [("../escape", tarfile.REGTYPE, ""),
                                 ("inside", tarfile.SYMTYPE, "../../escape")]:
            with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory() as tmp:
                source = Path(tmp) / "source.tar"
                with tarfile.open(source, "w:") as archive:
                    entry = tarfile.TarInfo(name)
                    entry.type = kind
                    entry.linkname = link
                    if kind == tarfile.REGTYPE:
                        entry.size = 1
                        archive.addfile(entry, io.BytesIO(b"x"))
                    else:
                        archive.addfile(entry)
                with self.assertRaises((RuntimeError, tarfile.TarError)):
                    scope["unpack"](source, Path(tmp) / "unpacked")
                self.assertFalse((Path(tmp) / "escape").exists())

    def test_fake_git_source_refused_before_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            source.mkdir()
            with self.assertRaises(RuntimeError):
                scope["source_archive"](source, Path(tmp) / "source.tar")
            self.assertFalse((Path(tmp) / "source.tar").exists())


if __name__ == "__main__":
    unittest.main()
