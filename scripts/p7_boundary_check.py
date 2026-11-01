"""P7 runtime import isolation plus changed core-source boundary inspection."""
import argparse
import ast
import hashlib
import importlib.abc
import json
from pathlib import Path
import sys
import traceback

TARGET=Path(__file__).resolve().parents[1]
BLOCKED={'angr','pyvex','claripy','idaapi','ida_hexrays','networkx'}
CORE=('core','ir','graph','memory','analysis')


class NativeBlocker(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname.split('.')[0] in BLOCKED:raise ImportError('P7 boundary forbids '+fullname)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source-root','before','folder'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();source=args.source_root.resolve();source.relative_to(TARGET)
    folder=args.folder.resolve();folder.relative_to(TARGET/'.p7-work');folder.mkdir(exist_ok=False)
    report={'source':str(source),'producer_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    sys.path.insert(0,str(source));sys.meta_path.insert(0,NativeBlocker())
    try:
        import emtaint.cli
        import emtaint.orchestration.taint_program
        modules=sorted(name for name in sys.modules if name.startswith('emtaint.'))
        before=json.loads(args.before.read_text());historical=[];changed=[]
        for name in CORE:
            for path in sorted((source/'emtaint'/name).rglob('*.py')):
                relative=path.relative_to(source).as_posix();data=path.read_bytes()
                unchanged=before.get(relative)==hashlib.sha256(data).hexdigest()
                for node in ast.walk(ast.parse(data.decode('utf-8-sig'))):
                    imports=[value.name for value in node.names] if isinstance(node,ast.Import) else [node.module or ''] if isinstance(node,ast.ImportFrom) else []
                    for module in imports:
                        if module.split('.')[0] in BLOCKED:
                            (historical if unchanged else changed).append({'file':relative,'line':node.lineno,'module':module})
        report.update(loaded_runtime_modules=modules,historical_preserved_native_imports=historical,changed_core_native_imports=changed,
            passed=not changed,scope='Actual P7 runtime imports; historical preserved native facades are reported separately')
    except BaseException as error:
        traceback.print_exc();report.update(passed=False,error=type(error).__name__+': '+str(error))
    with (folder/'report.json').open('x',encoding='utf8') as stream:json.dump(report,stream,indent=2)
    print(json.dumps({key:report[key] for key in ('passed','scope') if key in report}));return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
