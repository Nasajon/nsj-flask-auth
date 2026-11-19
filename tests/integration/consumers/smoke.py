"""HTTP smoke against actual nginx/FPM/uWSGI, controllers, SQL and pinned authority."""
import base64
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import re
import time
from urllib.parse import urlsplit
import uuid
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from probe import APPS,config,request

ROOT=Path('/fixture')
checks=[]
def check(label,app,path,expected=200,headers=None,method='GET',body=None,key='valid'):
    merged={'X-API-Key':config['keys'][key]} if key else {}
    merged.update(headers or {})
    status,reply,data=request(app,path,merged,method,body)
    safe=re.sub(r'nsa_[A-Za-z0-9_-]+','[REDACTED]',data[:400])
    assert status==expected,(label,status,safe)
    assert 'Set-Cookie' not in reply,(label,'Unexpected session cookie')
    assert 'X-Service-Account-Request' not in reply,(label,'Leaked internal log marker')
    assert all(k not in data for k in config['keys'].values()),(label,'Leaked key')
    checks.append(dict(label=label,app=app,status=status))
    try: return json.loads(data) if data else None
    except ValueError: return data

from signing import signed

# Wait for the actual upstream app, not merely nginx's listening socket.
for app in APPS:
    deadline=time.monotonic()+90
    while True:
        try:
            status,_,_=request(app,'/profile')
            if status not in (502,503):break
        except Exception:
            pass
        if time.monotonic()>deadline:raise RuntimeError(app+' did not become ready')
        time.sleep(1)
    print(app,'upstream ready',flush=True)

for app,path in APPS.items():
    data=check('reviewed-read',app,path)
    if app in ('atendimento','erp','roteirizacao'):
        text=json.dumps(data)
        assert 'Other tenant' not in text and 'Other vehicle' not in text
        assert data and len(data)==1
    for mode in ['no-provision','restricted','ip']:
        extra={'X-Real-IP':'203.0.113.1','X-Forwarded-For':'203.0.113.1'} if mode=='ip' else {}
        check(mode,app,path,403,headers=extra,key=mode)
    for mode in ['expired','revoked']:
        check(mode,app,path,401,key=mode)
    check('bearer-key',app,path,401,headers={'Authorization':'Bearer '+config['keys']['valid']},key=None)
    check('uppercase-key',app,path,401,headers={'X-API-Key':config['keys']['valid'].replace('nsa_','NSA_',1)},key=None)
    check('encoded-uri-key',app,'/'+config['keys']['valid'].replace('_','%255f'),401,key=None)
    status,_,_=request(app,'/profile' if app in ('atendimento','erp','roteirizacao') else path)
    assert status in (401,403), (app,'Leaked authenticated context',status)
    checks.append(dict(label='no-credential-after-technical-request',app=app,status=status))
    check('legacy-header-key',app,path,401,headers={'apikey':config['keys']['valid']},key=None)
    check('mixed-credentials',app,path,401,headers={'Authorization':'Bearer human'})
    check('query-key',app,path+('&' if '?' in path else '?')+'apikey='+config['keys']['valid'],401,key=None)
    check('head',app,path,403,method='HEAD')
    check('write',app,path,403,method='POST',body=b'{}')
    check('get-with-body',app,path,403,body=b'{}')
    check('method-override',app,path,403,headers={'X-HTTP-Method-Override':'POST'})
    wrong=path.replace('tenant=47','tenant=48') if app in ('estoque','tesouraria') else path.replace('/fixture/','/other/')
    check('cross-tenant',app,wrong,403)
    check('ambiguous-tenant',app,path+('&' if '?' in path else '?')+'tenant=other',403)
    blocked={'atendimento':'/profile','erp':'/profile','roteirizacao':'/profile','estoque':'/estoque-api/erp3/4311/tipos-fracoes','tesouraria':'/tesouraria/erp3/284/ordem_pagamento'}[app]
    check('human-or-unreviewed-route',app,blocked,403,method='POST' if app=='tesouraria' else 'GET',body=b'{}' if app=='tesouraria' else None)
    for algorithm in ['ed25519','ecdsa-p256-sha256']:
        headers=signed(app,path,algorithm=algorithm)
        check('signed-'+algorithm,app,path,headers=headers,key='signed')
        check('replay-'+algorithm,app,path,403,headers=headers,key='signed')
        unsigned_tenant=signed(app,path,algorithm=algorithm,cover_tenant=False)
        check('unsigned-tenant-'+algorithm,app,path,403,headers=unsigned_tenant,key='signed')
        tampered=signed(app,path,algorithm=algorithm);tampered['X-Tenant']='48' if app in ('estoque','tesouraria') else 'other'
        check('tampered-tenant-'+algorithm,app,path,403,headers=tampered,key='signed')
    print(app,'basic scope/transport/crypto checks passed',flush=True)
# Same nonce, separately valid signatures over each consumer's original URI: a global replay must fail.
nonce=uuid.uuid4().hex
for index,(app,path) in enumerate(APPS.items()):
    check('cross-consumer-nonce',app,path,200 if index==0 else 403,headers=signed(app,path,nonce=nonce),key='signed')
# Exact detail routes and cross-tenant IDs preserve business 404s.
check('supplier-detail','erp','/fixture/G/fornecedores/00000000-0000-4000-8000-000000000015')
check('supplier-other-tenant-id','erp','/fixture/G/fornecedores/00000000-0000-4000-8000-000000000016',404)
check('vehicle-detail','roteirizacao','/api/v1/fixture/G/veiculos/00000000-0000-4000-8000-000000000033')
check('vehicle-other-tenant-id','roteirizacao','/api/v1/fixture/G/veiculos/00000000-0000-4000-8000-000000000034',404)
check('legacy-v2-read','roteirizacao',APPS['roteirizacao'].replace('/v1/','/v2/'))
check('title-detail','tesouraria','/tesouraria/erp3/284/titulos/pagamentos/00000000-0000-4000-8000-000000000029?tenant=47')
check('title-not-found','tesouraria','/tesouraria/erp3/284/titulos/pagamentos/00000000-0000-4000-8000-000000999999?tenant=47',404)
I='00000000-0000-0000-0000-000000000004';S='00000000-0000-0000-0000-000000000003';L='00000000-0000-4000-8000-000000000005'
paths=[
 ('estoque',f'/estoque-api/erp3/4311/saldos-produtos?tenant=47&id_item={I}&id_estabelecimento={S}&atualizado_apos=2026-10-01'),
 ('estoque',f'/estoque-api/erp3/4311/saldos-locais-estoque?tenant=47&id_item={I}&id_estabelecimento={S}&id_local_estoque={L}'),
 ('estoque',f'/estoque-api/erp3/4311/saldos-locais-estoques-enderecos?tenant=47&item={I}&estabelecimento={S}&local_estoque={L}'),
 ('tesouraria','/tesouraria/erp3/284/titulos/recebimentos?tenant=47'),
]
for app,path in paths:
    data=check('remaining-reviewed-read',app,path)
    assert data, (app,'Expected fixture data')
# Keep replay evidence available for the Redis recovery phase without saving a secret in reports.
(ROOT/'.local/replay.json').write_text(json.dumps(dict(app='atendimento',path=APPS['atendimento'],headers=signed('atendimento',APPS['atendimento']))))
replay=json.loads((ROOT/'.local/replay.json').read_text())
check('before-redis-recovery',replay['app'],replay['path'],headers=replay['headers'],key='signed')
(ROOT/'.local/http-evidence.json').write_text(json.dumps(checks,indent=2))
print(len(checks),'actual HTTP checks passed',flush=True)
