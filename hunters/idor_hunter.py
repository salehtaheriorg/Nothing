from __future__ import annotations
import json
import re
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import difflib
import requests

from hunters.base_hunter import BaseHunter

ID_PARAM_PATTERN = re.compile(r'^(id|uid|user_?id|account_?id|order_?id|invoice_?id|doc(ument)?_?id|file_?id|profile_?id|customer_?id|ref|reference)$', re.I)
UUID_PATTERN = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)

def find_id_like_params(url: str) -> list[tuple[str,str]]:
    params = parse_qs(urlparse(url).query, keep_blank_values=True)
    out=[]
    for k, vals in params.items():
        if not vals: continue
        v=vals[0]
        if ID_PARAM_PATTERN.match(k) or v.isdigit() or UUID_PATTERN.match(v): out.append((k,v))
    return out

def find_id_like_path_segments(url: str) -> list[tuple[str,str,int]]:
    parts=[p for p in urlparse(url).path.split('/') if p]
    out=[]
    for idx,v in enumerate(parts):
        if v.isdigit() or UUID_PATTERN.match(v) or re.fullmatch(r'[a-f0-9]{16,64}',v,re.I): out.append(('__path__',v,idx))
    return out

def _set_query_param(url,key,value):
    p=urlparse(url); q=parse_qs(p.query,keep_blank_values=True); q[key]=[value]
    return urlunparse(p._replace(query=urlencode(q,doseq=True)))

def _set_path_segment(url,index,value):
    p=urlparse(url); parts=p.path.split('/'); pos=[i for i,x in enumerate(parts) if x]
    if index>=len(pos): return url
    parts[pos[index]]=value
    return urlunparse(p._replace(path='/'.join(parts)))

def _load_sessions(path=None):
    if path is None:
        path = str(Path(__file__).resolve().parent.parent / 'config' / 'auth.json')
    p=Path(path)
    if not p.exists(): return {}
    try: return json.loads(p.read_text(encoding='utf-8'))
    except Exception: return {}

class IDORHunter(BaseHunter):
    name='idor'
    def __init__(self,*args,auth_file='config/auth.json',**kwargs):
        super().__init__(*args,**kwargs); self.sessions=_load_sessions(auth_file)

    def execute(self,target,payload):
        url=payload.get('url',target); params=find_id_like_params(url); paths=find_id_like_path_segments(url)
        if not params and not paths: return {'target':url,'status':'no_id_locations_found','findings':[]}
        findings=[]
        for k,v in params: findings += self._test_param(url,k,v)
        for _,v,idx in paths: findings += self._test_path(url,idx,v)
        return {'target':url,'query_params_tested':[x[0] for x in params],'path_segments_tested':[x[1] for x in paths],'findings':findings}

    def _request(self,url,session):
        self.rate_limiter.wait(); headers=dict((session or {}).get('headers') or {}); cookies={}
        c=(session or {}).get('cookie','')
        for part in c.split(';'):
            if '=' in part:
                k,v=part.strip().split('=',1); cookies[k]=v
        try:
            r=requests.get(url,headers=headers,cookies=cookies,timeout=10,allow_redirects=False)
            text=r.text[:12000]
            return {'status':r.status_code,'length':len(r.content),'text':text,'content_type':r.headers.get('Content-Type','')}
        except requests.RequestException: return None

    @staticmethod
    def _same_representation(a,b):
        if not a or not b: return False
        if a['status'] != b['status']: return False
        sim=difflib.SequenceMatcher(None,a['text'],b['text'],autojunk=False).ratio()
        return sim >= 0.92 and abs(a['length']-b['length'])/max(a['length'],1) < 0.15

    @staticmethod
    def _meaningfully_different(a,b):
        if not a or not b: return False
        sim=difflib.SequenceMatcher(None,a['text'],b['text'],autojunk=False).ratio()
        return a['status'] in (200,206) and b['status'] in (200,206) and sim < 0.92

    def _test_param(self,url,param,value):
        a=self.sessions.get('session_a'); b=self.sessions.get('session_b')
        if not a or not a.get('cookie'): return []
        baseline=self._request(url,a)
        if not baseline: return []
        findings=[]
        anon=self._request(url,None)
        if anon and baseline['status'] in (200,206) and anon['status'] in (200,206) and self._same_representation(baseline,anon):
            findings.append(self.report_finding(url,'Broken Access Control (unauthenticated access)','high',{
                'param':param,'authenticated':{'status':baseline['status'],'length':baseline['length']},'anonymous':{'status':anon['status'],'length':anon['length']},'manual_verification_required':True}))
        if b and b.get('cookie'):
            cross=self._request(url,b)
            if cross and self._same_representation(baseline,cross):
                findings.append(self.report_finding(url,'Potential IDOR (cross-account response equivalence)','high',{
                    'param':param,'session_a':{'status':baseline['status'],'length':baseline['length']},'session_b':{'status':cross['status'],'length':cross['length']},'note':'Response equivalence is a signal only; verify resource ownership with dedicated test accounts.'}))
        if value.isdigit():
            for new in (str(int(value)+1),str(max(0,int(value)-1))):
                modified=self._request(_set_query_param(url,param,new),a)
                if modified and self._meaningfully_different(baseline,modified):
                    findings.append(self.report_finding(_set_query_param(url,param,new),'Potential Sequential-ID Access','medium',{
                        'param':param,'original_value':value,'tested_value':new,'baseline_status':baseline['status'],'modified_status':modified['status'],'body_similarity':round(difflib.SequenceMatcher(None,baseline['text'],modified['text'],autojunk=False).ratio(),4),'manual_verification_required':True}))
        return findings

    def _test_path(self,url,index,value):
        a=self.sessions.get('session_a')
        if not a or not a.get('cookie'): return []
        base=self._request(url,a)
        if not base or base['status'] not in (200,206): return []
        variants=[str(int(value)+1),str(max(0,int(value)-1))] if value.isdigit() else (['00000000-0000-0000-0000-000000000000'] if UUID_PATTERN.match(value) else ['0000000000000000'])
        findings=[]
        for new in variants:
            modified=self._request(_set_path_segment(url,index,new),a)
            if modified and self._meaningfully_different(base,modified):
                findings.append(self.report_finding(url,'Potential IDOR (path identifier)','medium',{'segment_index':index,'original_value':value,'tested_value':new,'body_similarity':round(difflib.SequenceMatcher(None,base['text'],modified['text'],autojunk=False).ratio(),4),'manual_verification_required':True}))
        return findings
