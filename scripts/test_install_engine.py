"""Offline failure-path checks for verified engine installation."""
from pathlib import Path
import tempfile
import unittest

from install_engine import install


class InstallationTests(unittest.TestCase):
    def test_corrupt_archive_is_rejected_without_installing(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            archive = root/'corrupt.tar.gz'
            archive.write_bytes(b'not a reviewed release archive')
            with self.assertRaisesRegex(ValueError, 'checksum'):
                install(root/'engine', archive)
            self.assertEqual(list((root/'engine').iterdir()), [])

    def test_failed_replacement_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            archive = root/'corrupt.zip'
            archive.write_bytes(b'untrusted archive bytes')
            directory = root/'engine'
            directory.mkdir()
            original = directory/'betterleaks'
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


if __name__ == '__main__':
    unittest.main()
