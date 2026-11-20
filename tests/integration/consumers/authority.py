"""Actual pinned auth service/DAO; legacy profiles, OAuth client and Multidb are contract fixtures."""
import json
import logging
import re
import sys
from pathlib import Path
import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask,jsonify,request
sys.path.insert(0,'/fixture/.local/authority-source')
from nsj_diretorio_authz.service.service_account_auth_service import ServiceAccountAuthService
from nsj_diretorio_authz.dao.service_account_auth_dao import ServiceAccountAuthDAO
from nsj_diretorio_authz.exception import UnauthorizedError

def connection():
    return psycopg2.connect(host='postgres',dbname='service_account_smoke',user='fixture',password='fixture-local-only')
class Adapter:
    def execute_query(self,sql,**params):
        with connection() as db,db.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(re.sub(r'(?<!:):([A-Za-z_]\w*)',r'%(\1)s',sql),params)
            return list(cursor.fetchall())
app=Flask(__name__)
@app.before_request
def protect_other_services():
    if request.path=='/authz-api/service-accounts/authenticate':return
    if 'nsa_' in str((list(request.headers.items()),request.args.to_dict(),request.get_data(as_text=True))):
        with connection() as db,db.cursor() as c:c.execute('INSERT INTO fixture.violations DEFAULT VALUES')
        return jsonify(message='Incoming service key reached a forbidden destination'),500
@app.post('/authz-api/service-accounts/authenticate')
def authenticate():
    try:return jsonify(ServiceAccountAuthService(ServiceAccountAuthDAO(Adapter()),'fixture-pepper-only').autenticar((request.get_json(silent=True) or {}).get('key','')))
    except UnauthorizedError:return jsonify(message='Credencial inválida.'),401
@app.get('/v2/api/profile/<email>')
def profile(email):
    if request.headers.get('apikey')!='fixture-legacy-application-key':return jsonify(message='Bad application key'),401
    with connection() as db,db.cursor() as c:
        c.execute('SELECT profile FROM fixture.profiles WHERE email=%s',(email,));row=c.fetchone()
    return jsonify(row[0]) if row else (jsonify(message='Missing profile'),404)
@app.get('/v2/api/funcoes/<function>/permissoes')
def permissions(function):
    if request.headers.get('apikey')!='fixture-legacy-application-key':return jsonify(message='Bad application key'),401
    return jsonify(['ns_fornecedores_index','ns_fornecedores_get'] if function=='read-suppliers' else [])
@app.post('/token')
def token():
    credentials=request.authorization
    if not credentials or credentials.username not in ('estoque-api','tesouraria-api') or credentials.password!='fixture-client-secret':return jsonify(message='Bad client'),401
    if request.form.get('grant_type')!='client_credentials' or request.form.get('audience')!='nsj-multidb-api':return jsonify(message='Bad grant'),400
    return jsonify(access_token='fixture-multidb-only',token_type='Bearer',expires_in=300)
@app.get('/v1/erp/credentials')
def credentials():
    if request.headers.get('Authorization')!='Bearer fixture-multidb-only':return jsonify(message='Bad API token'),401
    if request.args.get('tenant')!='47':return jsonify(message='Wrong tenant'),403
    email=request.args.get('service_account','')
    with connection() as db,db.cursor() as c:
        c.execute('SELECT id FROM diretorio.contas WHERE email=%s AND tipo=\'SERVICO\'',(email,));row=c.fetchone()
    if not row:return jsonify(message='Unknown account'),403
    return jsonify(hostname='postgres',port=5432,db_name='business47',user='sa_'+str(row[0]),password='fixture-business-only',user_id='11111111-1111-1111-1111-111111111111')
@app.get('/ready')
def ready():return jsonify(ok=True)
if __name__=='__main__':
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    app.run(host='0.0.0.0',port=8080,threaded=True)
