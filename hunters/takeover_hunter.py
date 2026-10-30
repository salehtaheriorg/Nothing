from __future__ import annotations
import json
from pathlib import Path
import requests
try:
    import dns.resolver
    HAS_DNS=True
except ImportError:
    HAS_DNS=False
from hunters.base_hunter import BaseHunter

DEFAULT_FINGERPRINTS_FILE='config/takeover_fingerprints.json'

def _load(path):
    p=Path(path)
    if not p.exists(): return []
    try: return json.loads(p.read_text(encoding='utf-8'))
    except Exception: return []

def resolve_records(host):
    if not HAS_DNS: return {'cname':None,'a':[],'aaaa':[]}
    out={'cname':None,'a':[],'aaaa':[]}
    try: out['cname']=str(dns.resolver.resolve(host,'CNAME',lifetime=4)[0].target).rstrip('.')
    except Exception: pass
    for typ,key in (('A','a'),('AAAA','aaaa')):
        try: out[key]=[str(x) for x in dns.resolver.resolve(host,typ,lifetime=4)]
        except Exception: pass
    return out

class TakeoverHunter(BaseHunter):
    name='takeover'
    def __init__(self,*args,fingerprints_file=DEFAULT_FINGERPRINTS_FILE,**kwargs):
        super().__init__(*args,**kwargs); self.fingerprints=_load(fingerprints_file)
    def execute(self,target,payload):
        if not HAS_DNS: return {'target':target,'warning':'dnspython نصب نیست','findings':[]}
        dnsinfo=resolve_records(target); cname=dnsinfo['cname']
        if not cname: return {'target':target,'status':'no_cname','dns':dnsinfo,'findings':[]}
        fp=self._match(cname)
        if not fp: return {'target':target,'status':'cname_not_matching_known_service','cname':cname,'dns':dnsinfo,'findings':[]}
        self.rate_limiter.wait()
        try: r=requests.get(f'https://{target}',timeout=10,allow_redirects=False)
        except requests.RequestException:
            return {'target':target,'status':'unreachable','cname':cname,'matched_service':fp.get('service'),'findings':[]}
        text=r.text.lower(); signature=str(fp.get('response_signature','')).lower()
        if signature and signature in text:
            fid=self.report_finding(target,f"Subdomain Takeover ({fp.get('service','unknown')})",'high',{ 
                'cname':cname,'dns':dnsinfo,'service':fp.get('service'),'http_status':r.status_code,'signature':fp.get('response_signature'),'docs':fp.get('docs_url'),'manual_verification_required':True}, 'candidate')
            return {'target':target,'cname':cname,'service':fp.get('service'),'findings':[fid]}
        return {'target':target,'cname':cname,'service':fp.get('service'),'status':'service_match_without_unclaimed_signature','http_status':r.status_code,'findings':[]}
    def _match(self,cname):
        low=cname.lower()
        for fp in self.fingerprints:
            if any(str(x).lower() in low for x in fp.get('cname_indicators',[])): return fp
        return None
