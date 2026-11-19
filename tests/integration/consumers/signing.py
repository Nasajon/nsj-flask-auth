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
def signed(app,path,nonce=None,algorithm='ed25519',cover_tenant=True):
    key_name='ed25519' if algorithm=='ed25519' else 'p256'
    private=serialization.load_pem_private_key((ROOT/'.local'/f'{key_name}.pem').read_bytes(),password=None)
    tenant='47' if app in ('estoque','tesouraria') else 'fixture'
    parts=urlsplit(path)
    fields=['@method','@path']+(['@query'] if parts.query else [])+(['x-tenant'] if cover_tenant else [])
    params='('+' '.join('"'+f+'"' for f in fields)+f');created={int(time.time())};nonce="{nonce or uuid.uuid4().hex}";keyid="{key_name}";alg="{algorithm}"'
    values={'@method':'GET','@path':parts.path,'@query':'?'+parts.query,'x-tenant':tenant}
    base='\n'.join([f'"{f}": {values[f]}' for f in fields]+['"@signature-params": '+params]).encode()
    if algorithm=='ed25519':signature=private.sign(base)
    else:
        r,s=decode_dss_signature(private.sign(base,ec.ECDSA(hashes.SHA256())))
        signature=r.to_bytes(32,'big')+s.to_bytes(32,'big')
    return {'X-Tenant':tenant,'Signature-Input':'sig1='+params,'Signature':'sig1=:'+base64.b64encode(signature).decode()+':'}

