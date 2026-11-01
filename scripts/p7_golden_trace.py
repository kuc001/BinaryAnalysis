"""Extract original raw trace evidence for post-analysis review only."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re

TARGET=Path(__file__).resolve().parents[1]
COPY=re.compile(r'check-weak-copy(?:-length)?: (0x[0-9a-f]+).*? with (\[.*?\]) ([0-9a-f]+) inter-level\(icall\):\s*(\d+)\((\d+)\) (\[.*\])')
COMMAND=re.compile(r'Good, find taint in (\w+)! <Block (0x[0-9a-f]+)->.*? \((0x[0-9a-f]+)\)>.*? (0x[0-9a-f]+) (\d+)$')
PATH=re.compile(r'check-command-injection: ([0-9a-f]+) (\[.*\])')
COPY_LENGTH=re.compile(r'check-weak-copy-with-lenth: (0x[0-9a-f]+).*? with (\[.*\])$')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--golden',type=Path,required=True);parser.add_argument('--folder',type=Path,required=True)
    args=parser.parse_args();folder=args.folder.resolve();folder.relative_to(TARGET/'.p7-work');folder.mkdir(exist_ok=False)
    log=args.golden/'taint.log';data=json.loads((args.golden/'taint.json').read_text())['taint_1'];records={};errors=[]
    for number,line in enumerate(log.read_text(encoding='utf8',errors='replace').splitlines(),1):
        match=COPY.search(line)
        if match:
            site,constraints,source,level,indirect,path=match.groups();site=int(site,16)
            try:values=ast.literal_eval(constraints);functions=[int(value,16) for value in ast.literal_eval(path)]
            except (ValueError,SyntaxError,TypeError) as error:errors.append({'line':number,'reason':str(error),'raw':line});continue
            records.setdefault(site,[]).append({'kind':'copy','line':number,'source':int(source,16),'constraints':values,
                'legacy_inter_level':int(level),'legacy_indirect_level':int(indirect),'function_path':functions,'raw':line})
        match=COMMAND.search(line)
        if match:
            name,site,function,source,level=match.groups()
            records.setdefault(int(site,16),[]).append({'kind':'command','line':number,'name':name,'function':int(function,16),
                'source':int(source,16),'legacy_inter_level':int(level),'raw':line})
        match=COPY_LENGTH.search(line)
        if match:
            site,constraints=match.groups()
            try:values=ast.literal_eval(constraints)
            except (ValueError,SyntaxError,TypeError) as error:errors.append({'line':number,'reason':str(error),'raw':line});continue
            records.setdefault(int(site,16),[]).append({'kind':'copy-and-tainted-length','line':number,'constraints':values,
                'source_not_printed_by_legacy_branch':True,'raw':line})
        match=PATH.search(line)
        if match:
            site,path=match.groups()
            try:functions=[int(value,16) for value in ast.literal_eval(path)]
            except (ValueError,SyntaxError,TypeError) as error:errors.append({'line':number,'reason':str(error),'raw':line});continue
            records.setdefault(int(site,16),[]).append({'kind':'command-path','line':number,'function_path':functions,'raw':line})
    rows=[]
    for category in ('buffer_overflow','command_exec'):
        for key,expected in data[category].items():
            site=int(key,16);evidence=records.get(site,[])
            rows.append({'category':category,'site':site,'function':expected['func'],'name':expected['name'],
                'offsets':expected.get('offset',[]),'sources':sorted({row['source'] for row in evidence if 'source' in row}),
                'raw_evidence':evidence,'missing_raw_source':not any('source' in row for row in evidence)})
    report={'rows':rows,'parser_errors':errors,'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest(),
        'golden_sha256':hashlib.sha256((args.golden/'taint.json').read_bytes()).hexdigest(),
        'scope':'Old heuristic trace facts, not solver-validated paths; never an input to the new analysis engine'}
    with (folder/'trace-evidence.json').open('x',encoding='utf8') as stream:json.dump(report,stream,indent=2)
    print(json.dumps({'rows':len(rows),'missing_raw_source':sum(row['missing_raw_source'] for row in rows),'parser_errors':len(errors)}));return 0


if __name__=='__main__':raise SystemExit(main())
