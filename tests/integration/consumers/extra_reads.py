"""Remaining declared reads; actual DTO/DAO paths on the isolated ERP database."""
import sys
sys.path.insert(0,'/fixture')
from probe import request,config
I='00000000-0000-0000-0000-000000000004';S='00000000-0000-0000-0000-000000000003';L='00000000-0000-4000-8000-000000000005'
paths=[
 ('estoque',f'/estoque-api/erp3/4311/saldos-produtos?tenant=47&id_item={I}&id_estabelecimento={S}&atualizado_apos=2026-10-01'),
 ('estoque',f'/estoque-api/erp3/4311/saldos-locais-estoque?tenant=47&id_item={I}&id_estabelecimento={S}&id_local_estoque={L}'),
 ('estoque',f'/estoque-api/erp3/4311/saldos-locais-estoques-enderecos?tenant=47&item={I}&estabelecimento={S}&local_estoque={L}'),
 ('tesouraria','/tesouraria/erp3/284/titulos/recebimentos?tenant=47'),
]
for app,path in paths:
 status,_,body=request(app,path,{'X-API-Key':config['keys']['valid']})
 print(app,path.split('?')[0],status,body[:500],flush=True)
