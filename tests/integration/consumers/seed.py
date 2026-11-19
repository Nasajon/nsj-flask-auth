"""Disposable schemas/data; not a business migration and never a production dump."""
import ast
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import uuid
import xml.etree.ElementTree as ET
import psycopg2
from psycopg2.extras import Json
from cryptography.hazmat.primitives.asymmetric import ed25519,ec
from cryptography.hazmat.primitives import serialization
ROOT=Path('/fixture');WORK=Path('/workspace')
GROUP='00000000-0000-0000-0000-000000000001'
COMPANY='00000000-0000-0000-0000-000000000002'
SITE='00000000-0000-0000-0000-000000000003'
ITEM='00000000-0000-0000-0000-000000000004'
def connect(name='service_account_smoke'):
    return psycopg2.connect(host='postgres',dbname=name,user='fixture',password='fixture-local-only')
config={'keys':{},'emails':{}}
with connect() as db,db.cursor() as c:
    c.execute((ROOT/'authority.sql').read_text())
    for index,mode in enumerate(['valid','no-provision','restricted','revoked','expired','signed','ip'],77):
        email='serv_acc_'+hashlib.md5(mode.encode()).hexdigest()+'@svc.nasajon.app'
        prefix=f'{index:08d}';secret=secrets.token_urlsafe(32);key=f'nsa_{prefix}_{secret}'
        config['keys'][mode]=key;config['emails'][mode]=email
        c.execute('INSERT INTO diretorio.contas VALUES (%s,%s,%s,1,\'SERVICO\')',(index,email,mode))
        c.execute("INSERT INTO diretoriov2.service_accounts(conta_id,tenant,require_signature,allowed_cidrs) VALUES (%s,47,%s,%s::cidr[])",
            (index,mode=='signed',['203.0.113.0/24'] if mode=='ip' else []))
        digest=hmac.new(b'fixture-pepper-only',secret.encode(),hashlib.sha256).hexdigest()
        c.execute("INSERT INTO diretoriov2.service_account_keys VALUES (%s,%s,%s,now()+CASE WHEN %s THEN interval '-1 day' ELSE interval '1 day' END,CASE WHEN %s THEN now() ELSE NULL END)",
            (prefix,index,digest,mode=='expired',mode=='revoked'))
        funcs=[] if mode=='no-provision' else [dict(id=1,codigo='USUARIO',nome='Fixture'),dict(id=2,codigo='READ',nome='Fixture')]
        groupfunc=[] if mode=='no-provision' else [dict(id='read-suppliers',nome='Read',perfilfuncionarios=1,perfilclientes=1,perfilprojetos=1,departamento=None,carteira=None,sistemas=['297'])]
        tenant=dict(id=47,codigo='fixture',administrador=True,gruposempresariais=[dict(id=GROUP,codigo='G',nome='Group',funcoes=groupfunc)],
            sistemas=[dict(id=664,codigo='fixture',nome='Fixture',logo='',icone='',funcoes=funcs,entidades={'empresa':[COMPANY]} if mode=='restricted' else [])])
        if mode=='restricted':tenant['gruposempresariais'][0]['funcoes']=[]
        c.execute('INSERT INTO fixture.profiles VALUES (%s,%s)',(email,Json(dict(id=index,email=email,nome=mode,sobrenome='',tipo='SERVICO',tenants=[tenant]))))
        if mode=='signed':
            for label,private,algorithm in [('ed25519',ed25519.Ed25519PrivateKey.generate(),'ed25519'),('p256',ec.generate_private_key(ec.SECP256R1()),'ecdsa-p256-sha256')]:
                pem=private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
                c.execute('INSERT INTO diretoriov2.service_account_public_keys VALUES (%s,%s,%s,%s,NULL)',(index,label,algorithm,pem))
                target=ROOT/'.local'/f'{label}.pem';target.write_bytes(private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));target.chmod(0o600)
# Superset schema for just the reviewed read paths, sourced from tracked XML/entities.
tables={}
def add(table,col,typ='text'):
    if not re.fullmatch(r'\w+\.\w+',table) or not re.fullmatch(r'\w+',col):return
    tables.setdefault(table,{}).setdefault(col,typ)
def dtype(label):
    if 'UUID' in label or label in ('guid','object'):return 'uuid'
    if any(x in label for x in ['integer','int','IntEnum']):return 'integer'
    if 'bool' in label:return 'boolean'
    if any(x in label for x in ['Decimal','float','numeric','decimal']):return 'numeric'
    if any(x in label for x in ['datetime','timestamp','date']):return 'timestamp'
    return 'text'
for file in (WORK/'estoque-backend-contas-servico-dev/xmls').rglob('*.xml'):
    try:root=ET.parse(file).getroot()
    except ET.ParseError:continue
    entity=root.find('entity')
    if entity is None:continue
    table=entity.get('schema','')+'.'+entity.get('table','')
    if table not in ['estoque.veiculos','estoque.motoristas','estoque.combustiveis','estoque.tipos_veiculos','estoque.entregadores','estoque.veiculos_entregadores','ns.empresas']:continue
    for field in entity.findall('fieldmodel'):
        if field.get('datatype')=='objectlist':continue
        add(table,field.get('column',field.get('name','')),dtype(field.get('datatype','')))
    add(table,'tenant','integer')
for repo in ['estoque-api','tesouraria-api']:
    for file in (WORK/(repo+'-contas-servico-dev')/'nasajon/entity').rglob('*.py'):
        try:tree=ast.parse(file.read_text())
        except (SyntaxError,UnicodeDecodeError):continue
        for cls in [n for n in tree.body if isinstance(n,ast.ClassDef)]:
            table=None
            for decorator in cls.decorator_list:
                if isinstance(decorator,ast.Call):
                    for kw in decorator.keywords:
                        if kw.arg=='table_name' and isinstance(kw.value,ast.Constant):table=kw.value.value
            for method in cls.body:
                if isinstance(method,ast.FunctionDef) and method.name=='get_table_name':
                    for node in ast.walk(method):
                        if isinstance(node,ast.Return) and isinstance(node.value,ast.Constant):table=node.value.value
            if not table:continue
            for node in ast.walk(cls):
                if not isinstance(node,ast.AnnAssign):continue
                col=node.target.id if isinstance(node.target,ast.Name) else node.target.attr if isinstance(node.target,ast.Attribute) else ''
                if not col.startswith('_'):add(table,col,dtype(ast.unparse(node.annotation)))
# Schema columns used by the two existing PHP supplier queries; the view is a fixture table.
source=(WORK/'ErpApiWeb-contas-servico-dev/src/Nasajon/MDABundle/Repository/Ns/FornecedoresRepository.php').read_text()
for col in re.findall(r't0_\.(\w+)',source):add('ns.vw_fornecedores_v7',col,'integer' if col=='tenant' else 'uuid' if col in ('fornecedor','id_grupoempresarial') else 'text')
for alias,table in [('t1_','ns.vw_estabelecimentos'),('t2_','ns.formaspagamentos')]:
    for col in re.findall(alias+r'\.(\w+)',source):
        add(table,col,'integer' if col=='tenant' else 'uuid' if col in ('estabelecimento','grupoempresarial') else 'text')
tables['ns.vw_fornecedores_v7']['estabelecimentoid']='uuid'
tables['ns.vw_fornecedores_v7']['id_formapagamento_fornecedor']=tables['ns.formaspagamentos']['formapagamento']
for col,typ in [('pessoa','uuid'),('tenant','integer'),('tipoatividade','uuid')]: add('ns.pessoastiposatividades',col,typ)
for table,columns in {
 'ns.tenants':dict(tenant='bigint',codigo='text',nome='text',bloqueado='boolean'),
 'ns.gruposempresariais':dict(grupoempresarial='uuid',codigo='text',descricao='text',tenant='integer'),
 'servicos.atendimentostiposresolucoes':dict(atendimentotiporesolucao='uuid',descricao='text',tipo='integer',tenant='integer',atendimentoarea='uuid'),
}.items():
    for col,typ in columns.items():add(table,col,typ)
# Existing receiving-title DAO reads a browser view; this is a synthetic table.
source=(WORK/'tesouraria-api-contas-servico-dev/nasajon/dao/titulo_receber_dao.py').read_text().split('def get_titulo_completo',1)[1].split('def returnNumero',1)[0]
for col in set(re.findall(r'vwtit\.(\w+)',source)):
    typ='uuid' if col in ('id','id_pessoa','id_estabelecimento','conta','id_formapagamento') else 'integer' if col in ('situacao','sinal') else 'boolean' if col in ('adiantamento','estorno') else 'numeric' if col in ('valorbruto','saldotitulo','desconto','juros') else 'timestamp' if col in ('emissao','datacompetencia','vencimento','lastupdate') else 'text'
    add('financas.vwtitulosbrowser',col,typ)
for table,col,typ in [('ns.pessoas','id','uuid'),('ns.pessoas','nome','text'),('ns.estabelecimentos','estabelecimento','uuid'),('ns.estabelecimentos','codigo','text'),('financas.contas','conta','uuid'),('financas.contas','nome','text'),('ns.formaspagamentos','descricao','text')]:add(table,col,typ)
for table,col,typ in [('estoque.saldoslocaisdeestoques','slot','text'),('estoque.saldoslocaisdeestoquesenderecos','slot','text'),('estoque.saldoslocaisdeestoquesenderecos','saldolocaldeestoque','uuid')]:add(table,col,typ)
# A dedicated database represents one tenant, as the old APIs' entity models expect.
admin=connect();admin.autocommit=True
with admin.cursor() as c:c.execute('CREATE DATABASE business47')
admin.close()
for name in ['service_account_smoke','business47']:
    with connect(name) as db,db.cursor() as c:
        schemas={t.split('.')[0] for t in tables}
        for schema in schemas:c.execute('CREATE SCHEMA IF NOT EXISTS '+schema)
        for table,columns in tables.items():
            c.execute('CREATE TABLE IF NOT EXISTS '+table+' ('+', '.join('"'+col+'" '+typ for col,typ in columns.items())+')')
        c.execute("INSERT INTO ns.tenants(tenant,codigo,nome,bloqueado) VALUES (47,'fixture','Fixture',false),(48,'other','Other',false)")
        c.execute("INSERT INTO ns.gruposempresariais(grupoempresarial,codigo,descricao,tenant) VALUES (%s,'G','Group',47),(%s,'OTHER','Other',48)",(GROUP,str(uuid.UUID(int=101,version=4))))
        c.execute("INSERT INTO servicos.atendimentostiposresolucoes VALUES (%s,'Fixture allowed',0,47,NULL),(%s,'Other tenant',0,48,NULL)",(str(uuid.UUID(int=11,version=4)),str(uuid.UUID(int=12,version=4))))
        c.execute("INSERT INTO ns.vw_fornecedores_v7(fornecedor,nomefantasia,nome,tenant,id_grupoempresarial,status) VALUES (%s,'Allowed supplier','Allowed',47,%s,'0'),(%s,'Other tenant','Other',48,%s,'0')",(str(uuid.UUID(int=21,version=4)),GROUP,str(uuid.UUID(int=22,version=4)),str(uuid.UUID(int=101,version=4))))
        c.execute("INSERT INTO ns.empresas(empresa,codigo,razaosocial,tenant,grupoempresarial) VALUES (%s,'C','Allowed company',47,%s),(%s,'OTHER','Other company',48,%s)",(COMPANY,GROUP,str(uuid.UUID(int=102,version=4)),str(uuid.UUID(int=101,version=4))))
        c.execute("INSERT INTO estoque.veiculos(veiculo,codigo,modelo,placa,empresa,tenant) VALUES (%s,'V-001','Allowed vehicle','ABC1234',%s,47),(%s,'V-OTHER','Other vehicle','XYZ1234',%s,48)",(str(uuid.UUID(int=51,version=4)),COMPANY,str(uuid.UUID(int=52,version=4)),str(uuid.UUID(int=102,version=4))))
        if name=='business47':
            for table,pk in [('estoque.saldosestabelecimentos','saldoestabelecimento'),('estoque.saldoslocaisdeestoque','saldolocaldeestoque')]:
                if table in tables and pk in tables[table]:
                    cols=[pk,'saldo','data','item','estabelecimento'];values=[str(uuid.UUID(int=31,version=4)),10,'2026-11-01',ITEM,SITE]
                    c.execute('INSERT INTO '+table+' ('+','.join(cols)+') VALUES ('+','.join(['%s']*len(cols))+')',values)
            I=ITEM;S=SITE;L='00000000-0000-4000-8000-000000000005';A='00000000-0000-4000-8000-000000000006'
            c.execute("INSERT INTO estoque.itens(id,item,especificacao) VALUES (%s,'ITEM-001','Fixture')",(I,))
            c.execute("INSERT INTO estoque.locaisdeestoques(localdeestoque,estabelecimento,codigo,nome) VALUES (%s,%s,'LOCAL-001','Fixture')",(L,S))
            c.execute("INSERT INTO estoque.locaisdeestoquesenderecos(localdeestoqueendereco,localdeestoque,endereco,estabelecimento,analitico) VALUES (%s,%s,'A1',%s,true)",(A,L,S))
            c.execute("INSERT INTO estoque.saldoslocaisdeestoques(saldolocaldeestoque,estabelecimento,localdeestoque,item,slot,data,saldo) VALUES (%s,%s,%s,%s,'FISCAL','2026-11-01',10)",('00000000-0000-4000-8000-000000000020',S,L,I))
            c.execute("INSERT INTO estoque.saldoslocaisdeestoquesenderecos(id,saldolocaldeestoque,estabelecimento,localdeestoque,endereco,item,slot,data,saldo) VALUES (%s,%s,%s,%s,%s,%s,'FISCAL','2026-11-01',10)",('00000000-0000-4000-8000-000000000021','00000000-0000-4000-8000-000000000021',S,L,A,I))
            c.execute("INSERT INTO financas.vwtitulosbrowser(id,numero,sinal,adiantamento,estorno,situacao,valorbruto,saldotitulo) VALUES (%s,'REC-001',0,false,false,0,45.67,45.67)",(str(uuid.UUID(int=42,version=4)),))
            if 'financas.titulos' in tables:c.execute("INSERT INTO financas.titulos(id,numero,sinal,valor,situacao) VALUES (%s,'FIX-001',1,123.45,0)",(str(uuid.UUID(int=41,version=4)),))
with connect() as db,db.cursor() as c:
    for index in range(77,84):c.execute('CREATE ROLE sa_'+str(index)+" LOGIN PASSWORD 'fixture-business-only'")
with connect('business47') as db,db.cursor() as c:
    for index in range(77,84):
        for schema in {t.split('.')[0] for t in tables}:
            c.execute('GRANT USAGE ON SCHEMA '+schema+' TO sa_'+str(index));c.execute('GRANT SELECT ON ALL TABLES IN SCHEMA '+schema+' TO sa_'+str(index))
target=ROOT/'.local/config.json';target.write_text(json.dumps(config));target.chmod(0o600)
print('Seeded actual authority tables, synthetic provisions, and disposable business schemas')
