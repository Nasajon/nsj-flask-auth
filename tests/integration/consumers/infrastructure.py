"""One phase of real dependency-outage tests, driven by run-infrastructure.py."""
import json
from pathlib import Path
import sys
from probe import APPS,config,request
from signing import signed
phase=sys.argv[1]
checks=[]
for app,path in APPS.items():
    if phase=='redis-down':
        status,headers,_=request(app,path,{'X-API-Key':config['keys']['signed'],**signed(app,path)})
        assert status==503 and headers.get('Retry-After')=='1',(app,status)
        status,_,_=request(app,path,{'X-API-Key':config['keys']['valid']})
        assert status==200,(app,status)
    elif phase=='redis-up':
        replay=json.loads(Path('/fixture/.local/replay.json').read_text())
        if app=='atendimento':
            status,_,_=request(app,replay['path'],{'X-API-Key':config['keys']['signed'],**replay['headers']})
            assert status==403,('Persisted nonce',status)
        status,_,_=request(app,path,{'X-API-Key':config['keys']['signed'],**signed(app,path)})
        assert status==200,(app,status)
    elif phase=='authority-down':
        for key in ['valid','expired']:
            status,headers,_=request(app,path,{'X-API-Key':config['keys'][key]})
            assert status==503 and headers.get('Retry-After')=='1',(app,key,status)
    elif phase=='authority-up':
        for key,expected in [('valid',200),('expired',401)]:
            status,_,_=request(app,path,{'X-API-Key':config['keys'][key]})
            assert status==expected,(app,key,status)
    checks.append(dict(phase=phase,app=app,result='passed'))
    print(phase,app,'passed',flush=True)
Path('/fixture/.local/'+phase+'.json').write_text(json.dumps(checks,indent=2))
