from __future__ import annotations
import json
import os
import shutil
import subprocess
from collections import defaultdict
from hunters.base_hunter import BaseHunter

REPORTABLE={'critical','high','medium'}

class NucleiHunter(BaseHunter):
    name='nuclei'
    def execute(self,target,payload):
        binary=shutil.which('nuclei')
        if not binary: return {'target':target,'warning':'nuclei نصب نیست','findings':[]}
        timeout=float(os.getenv('NUCLEI_TIMEOUT','600'))
        self.rate_limiter.wait()
        try:
            proc=subprocess.run([binary,'-u',target,'-silent','-jsonl','-severity','critical,high,medium,low'],capture_output=True,text=True,timeout=timeout)
        except subprocess.TimeoutExpired:
            return {'target':target,'warning':'nuclei timeout شد','findings':[]}
        grouped=defaultdict(dict); findings=[]; invalid=0
        for line in proc.stdout.splitlines():
            line=line.strip()
            if not line: continue
            try: item=json.loads(line)
            except json.JSONDecodeError: invalid+=1; continue
            info=item.get('info') or {}; sev=str(info.get('severity','info')).lower(); tid=str(item.get('template-id','unknown')); matched=item.get('matched-at') or target
            if sev not in REPORTABLE: continue
            key=(matched,tid)
            grouped[key]={
                'template_id':tid,'severity':sev,'matched_at':matched,
                'name':info.get('name'),'description':info.get('description'),
                'reference':info.get('reference'),
                'matcher_name':item.get('matcher-name'),'type':item.get('type'),
            }
        for item in grouped.values():
            fid=self.report_finding(item['matched_at'],f"nuclei:{item['template_id']}",item['severity'],item,'candidate')
            findings.append(fid)
        return {'target':target,'findings':findings,'matches_considered':len(grouped),'invalid_json_lines':invalid,'returncode':proc.returncode}
