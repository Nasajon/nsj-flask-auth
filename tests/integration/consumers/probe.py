import json
from pathlib import Path
import urllib.request
import urllib.error
config=json.loads(Path('/fixture/.local/config.json').read_text())
APPS={
 'atendimento':'/api/admin/fixture/atendimentostiposresolucoes/',
 'erp':'/fixture/G/fornecedores/',
 'roteirizacao':'/api/v1/fixture/G/veiculos/',
 'estoque':'/estoque-api/erp3/4311/saldos?tenant=47&id_item=00000000-0000-0000-0000-000000000004&id_estabelecimento=00000000-0000-0000-0000-000000000003',
 'tesouraria':'/tesouraria/erp3/284/titulos/pagamentos?tenant=47&fields=id,numero',
}
def request(app,path,headers=None,method='GET',body=None):
    req=urllib.request.Request('http://'+app+path,headers=headers or {},method=method,data=body)
    try:
        with urllib.request.urlopen(req,timeout=60) as r:return r.status,dict(r.headers),r.read().decode()
    except urllib.error.HTTPError as e:return e.code,dict(e.headers),e.read().decode()
if __name__=='__main__':
    for app,path in APPS.items():
        try:
            status,headers,body=request(app,path,{'X-API-Key':config['keys']['valid']})
            print(app,status,body[:800],flush=True)
        except Exception as e:print(app,type(e).__name__,str(e))
