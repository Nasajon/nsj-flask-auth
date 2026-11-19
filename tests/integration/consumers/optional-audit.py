"""Run with unset or unreachable AUDIT_REDIS_URL: HTTP auth/replay must stay unchanged."""
import json
from pathlib import Path
import sys
import redis
from probe import APPS, config, request
from signing import signed

checks=[]
for app,path in APPS.items():
    status,_,_=request(app,path,{'X-API-Key':config['keys']['valid']})
    assert status==200,(app,'unsigned',status)
    headers={'X-API-Key':config['keys']['signed'],**signed(app,path)}
    status,_,_=request(app,path,headers)
    assert status==200,(app,'signed',status)
    status,_,_=request(app,path,headers)
    assert status==403,(app,'replay',status)
    status,_,_=request(app,path,{'Authorization':'Bearer '+config['keys']['valid']})
    assert status==401,(app,'bearer-key',status)
    checks.append(dict(app=app,unsigned=200,signed=200,replay=403,bearer_key=401))
    print(app,'optional audit: success and all protection checks passed',flush=True)
r=redis.Redis(host='redis')
assert not list(r.scan_iter(match='service-account:uso:*'))
assert not r.exists('service-account:ultimo-uso')
Path('/fixture/.local/optional-audit-'+sys.argv[1]+'.json').write_text(json.dumps(checks,indent=2))
