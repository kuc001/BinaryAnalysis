"""Run native scalar characterization with all caches in a fresh evidence dir."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

target=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(target));sys.path.insert(0,str(target/'tests'))
from p1_runtime import ProbeWriteGuard

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--folder',type=Path,required=True)
    folder=parser.parse_args().folder.resolve();folder.relative_to(target/'.p6-work')
    folder.mkdir(exist_ok=False);cache=folder/'cache';cache.mkdir()
    for name in ('TEMP','TMP','TMPDIR'):os.environ[name]=str(cache)
    tempfile.tempdir=str(cache)
    guard=ProbeWriteGuard([folder]).install()
    try:
        suite=unittest.defaultTestLoader.discover(str(target/'tests'),pattern='p6_scalar_native_cases.py')
        import p4_native_cases
        p4_native_cases.WORK=folder
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(p4_native_cases))
        with (folder/'tests.txt').open('x',encoding='utf8') as stream:
            result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
        report={'tests':result.testsRun,'success':result.wasSuccessful(),'violations':guard.violations}
        with (folder/'report.json').open('x',encoding='utf8') as stream:json.dump(report,stream,indent=2)
    finally:guard.restore()
    print(json.dumps(report));return 0 if report['success'] and not report['violations'] else 1

if __name__=='__main__':raise SystemExit(main())
