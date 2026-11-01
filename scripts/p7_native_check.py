"""Repeat accepted ARM scalar/frontend characterization in a fresh P7 folder."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

TARGET=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(TARGET),str(TARGET/'tests')]
from p1_runtime import ProbeWriteGuard


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--folder',type=Path,required=True)
    folder=parser.parse_args().folder.resolve();folder.relative_to(TARGET/'.p7-work');folder.mkdir(exist_ok=False)
    cache=folder/'cache';cache.mkdir()
    for name in ('TEMP','TMP','TMPDIR'):os.environ[name]=str(cache)
    tempfile.tempdir=str(cache);guard=ProbeWriteGuard([folder]).install()
    try:
        from emtaint.cli import source_manifest,process_metadata
        sources=source_manifest(TARGET)
        suite=unittest.defaultTestLoader.discover(str(TARGET/'tests'),pattern='p6_scalar_native_cases.py')
        import p4_native_cases
        p4_native_cases.WORK=folder;suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(p4_native_cases))
        with (folder/'tests.txt').open('x',encoding='utf8') as stream:
            result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
        report={'tests':result.testsRun,'success':result.wasSuccessful(),'violations':guard.violations,
            'source_unchanged':sources==source_manifest(TARGET),'source_manifest':sources,
            'producer_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),**process_metadata()}
        with (folder/'report.json').open('x',encoding='utf8') as stream:json.dump(report,stream,indent=2)
    finally:guard.restore()
    print(json.dumps({key:report[key] for key in ('tests','success','violations','source_unchanged')}))
    return 0 if report['success'] and not report['violations'] and report['source_unchanged'] else 1


if __name__=='__main__':raise SystemExit(main())
