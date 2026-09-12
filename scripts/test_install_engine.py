"""Offline failure-path checks for verified engine installation."""
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from install_engine import digest, install, matches_binary


class InstallationTests(unittest.TestCase):
    def test_existing_binary_digest_is_streamed_and_bounded(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / 'binary'
            data = b'a' * (1024 * 1024 + 3)
            path.write_bytes(data)
            self.assertTrue(matches_binary(path, digest(data)))
            self.assertFalse(matches_binary(path, '0' * 64))
            with patch('install_engine.MAX_BINARY', len(data) - 1), \
                    patch.object(Path, 'open', side_effect=AssertionError('Oversized cache was read')):
                self.assertFalse(matches_binary(path, digest(data)))
            path.write_bytes(b'abc')
            # The read limit still applies when bytes grow after the size check.
            with patch('install_engine.MAX_BINARY', 3), \
                    patch.object(Path, 'open', return_value=io.BytesIO(b'abcd')):
                self.assertFalse(matches_binary(path, digest(b'abcd')))

    def test_corrupt_archive_is_rejected_without_installing(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            archive = root/'corrupt.tar.gz'
            archive.write_bytes(b'not a reviewed release archive')
            with self.assertRaisesRegex(ValueError, 'checksum'):
                install(root/'engine', archive)
            self.assertEqual(list((root/'engine').iterdir()), [])

    def test_failed_replacement_preserves_existing_file(self):
        for system, machine, name in [('Darwin', 'arm64', 'betterleaks'),
                ('Linux', 'x86_64', 'betterleaks'), ('Windows', 'AMD64', 'betterleaks.exe')]:
            with self.subTest(system=system), tempfile.TemporaryDirectory() as work, \
                    patch('install_engine.platform.system', return_value=system), \
                    patch('install_engine.platform.machine', return_value=machine):
                root = Path(work)
                archive = root/'corrupt.zip'
                archive.write_bytes(b'untrusted archive bytes')
                directory = root/'engine'
                directory.mkdir()
                original = directory/name
                original.write_bytes(b'prior bytes')
                with self.assertRaisesRegex(ValueError, 'checksum'):
                    install(directory, archive)
                self.assertEqual(original.read_bytes(), b'prior bytes')
                self.assertEqual(list(directory.iterdir()), [original])

    def test_oversized_offline_archive_is_rejected_before_reading(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            archive = root/'oversized'
            with archive.open('wb') as file:
                file.truncate(129 * 1024 * 1024)
            with self.assertRaisesRegex(ValueError, 'size limit'):
                install(root/'engine', archive)
            archive.write_bytes(b'abc')
            original_open = Path.open
            def open_after_growth(path, *args, **kwargs):
                if path == archive:
                    return io.BytesIO(b'abcd')
                return original_open(path, *args, **kwargs)
            with patch('install_engine.MAX_ARCHIVE', 3), \
                    patch.object(Path, 'open', autospec=True, side_effect=open_after_growth), \
                    self.assertRaisesRegex(ValueError, 'size limit'):
                install(root/'engine', archive)


if __name__ == '__main__':
    unittest.main()
