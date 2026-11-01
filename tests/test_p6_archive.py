"""Complete unchanged P3 record archives reject tampering."""
import tempfile
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from p6_memory_archive import archive_memory,verify_archive
import test_p6_entry


class ArchiveTests(unittest.TestCase):
    def test_round_trip_and_tampered_record_hash(self):
        engine=test_p6_entry.EntryTests().image('legacy-loader-snapshot')
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            folder=Path(directory)/'arena';manifest=archive_memory(engine.snapshot(),folder)
            self.assertEqual(manifest['groups']['objects']['records'],len(engine.objects))
            self.assertTrue(verify_archive(folder))
            with (folder/'objects.jsonl').open('ab') as stream:stream.write(b'\n')
            with self.assertRaises((ValueError,TypeError)):verify_archive(folder)


if __name__=='__main__':unittest.main()
