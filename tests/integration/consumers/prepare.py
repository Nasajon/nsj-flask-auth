"""Generate a disposable local stack; never read developer .env/credentials."""
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent
WORK = Path(os.getenv('SERVICE_ACCOUNT_WORKSPACE', '/home/rodrigo/work'))
REVISION = '9953aef7cc7a342c81c4d3e656780fd50f9a048e'
local = ROOT / '.local'
local.mkdir(exist_ok=True)
for relative in ['exception.py', 'dao/base_dao.py', 'dao/service_account_auth_dao.py', 'service/service_account_auth_service.py']:
    target = local / 'authority-source/nsj_diretorio_authz' / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(subprocess.check_output(['git','-C',str(WORK/'nav'),'show',
        f'{REVISION}:platform/libs/backend/nsj-diretorio-authz/src/nsj_diretorio_authz/{relative}']))
stub=local/'authority-source/nsj_gcf_utils/db_adapter2.py'
stub.parent.mkdir(exist_ok=True);stub.write_text('class DBAdapter2: pass\n')
services = dict(
    postgres=dict(image=os.getenv('SERVICE_ACCOUNT_POSTGRES_IMAGE','postgres:16'), environment=dict(POSTGRES_DB='service_account_smoke',POSTGRES_USER='fixture',POSTGRES_PASSWORD='fixture-local-only'),
        command=['postgres','-c','log_statement=all','-c','log_line_prefix=%u@%d '],
        healthcheck=dict(test=['CMD-SHELL','pg_isready -U fixture'],interval='1s',retries=30)),
    redis=dict(image='redis:7.4-alpine',command=['redis-server','--appendonly','yes']),
    memcached=dict(image='memcached:1.6-alpine'),
    authority=dict(image='service-account-fixture:dev',command=['python','/fixture/authority.py'],
        volumes=[f'{ROOT}:/fixture:ro'],ports=['127.0.0.1:18900:8080']),
    client=dict(image='service-account-fixture:dev',entrypoint=['sleep','infinity'],volumes=[f'{ROOT}:/fixture:rw']),
)
apps = [('atendimento','Atendimento',18901),('erp','ErpApiWeb',18902),('roteirizacao','estoque-backend',18903)]
for name,repo,port in apps:
    path=WORK/(repo+'-contas-servico-dev')
    environment={}
    for directory in [path/'app/config',path/'src',path/'vendor/nasajon/login-bundle']:
        for file in directory.rglob('*'):
            if file.suffix not in ('.yaml','.yml','.xml') or not file.is_file():continue
            for key in re.findall(r'%env\((?:[a-z_]+:)*([A-Za-z_]\w*)\)%',file.read_text(errors='ignore')):
                value='fixture'
                if key.lower().endswith('port'):value='5432'
                if key.lower().endswith('host'):value='127.0.0.1'
                if key.lower().endswith('url'):value='http://127.0.0.1:9/'
                environment[key]=value
    environment.update(database_host='postgres',database_name='service_account_smoke',database_user='fixture',database_password='fixture-local-only',
        database_port='5432',database_timeoutmiliseconds='5000',database_driver='pdo_pgsql',database_server_version=os.getenv('SERVICE_ACCOUNT_POSTGRES_VERSION','16.1'),
        memcached_host='memcached',memcached_port='11211',api_key='fixture-legacy-application-key',
        diretorio_url='http://authority:8080/',diretorio_sistema_id='297' if name=='erp' else '664',
        AUTHORIZATION_API_URL='http://authority:8080/authz-api',SERVICE_ACCOUNT_REDIS_URL='redis://redis:6379/0',AUDIT_REDIS_URL=os.getenv('SERVICE_ACCOUNT_TEST_AUDIT_REDIS_URL',''),AUDIT_STREAM_KEY='audit:requests',AUDIT_SERVICE_NAME=name,
        SERVICE_ACCOUNT_TRUSTED_PROXIES='',SERVICE_ACCOUNT_IP_HEADER='X-Real-IP',SERVICE_ACCOUNT_READ_FUNCTIONS='READ',
        amazon_region='us-east-1',amazon_s3_version='2006-03-01',AWS_EC2_METADATA_DISABLED='true',SENTRY_DSN='',SENTRY_TEST_ENABLED='0',secret='fixture-only-secret-at-least-32-characters',
        sp_metadata='',sp_certificate_crt='',sp_certificate_pem='',ENV='local',locale='pt_BR')
    parameters=local/(name+'-parameters.yml');parameters.write_text('parameters:\n    locale: pt_BR\n    assets_version: fixture\n')
    conf=path/('default.conf' if name=='atendimento' else 'nginx/default.prod.conf' if name=='roteirizacao' else 'nginx/default.conf')
    mapping=path/('00-service-account-logging.conf' if name=='atendimento' else 'nginx/00-service-account-logging.conf')
    services[name]=dict(image='nasajon/php-simple:v0.0.5' if name=='roteirizacao' else 'meurh-service-accounts:dev',
        environment=environment,volumes=[f'{path}:/var/www/html:ro',f'{ROOT}/front.php:/var/www/html/web/app.php:ro',
            f'{parameters}:/var/www/html/app/config/parameters.yml:ro',f'{conf}:/etc/nginx/conf.d/default.conf:ro',
            f'{mapping}:/etc/nginx/conf.d/00-service-account-logging.conf:ro'],
        ports=[f'127.0.0.1:{port}:80'],tmpfs=['/tmp'], entrypoint=['sh','-ec','mkdir -p /tmp/nginx; chmod 1777 /tmp/nginx; exec /entrypoint.sh'])
for name,repo,port in [('estoque','estoque-api',18904),('tesouraria','tesouraria-api',18905)]:
    path=WORK/(repo+'-contas-servico-dev')
    environment=dict(PYTHONPATH='/shared:/var/www/html/.service-account-venv:/var/www/html',
        APP_NAME='estoque-api' if name=='estoque' else 'tesouraria',MOPE_CODE='284',ENV='local',
        DATABASE_HOST='postgres',DATABASE_PORT='5432',DATABASE_NAME='service_account_smoke',DATABASE_USER='fixture',DATABASE_PASS='fixture-local-only',
        MULTI_DATABASE_HOST='postgres',MULTI_DATABASE_PORT='5432',MULTI_DATABASE_NAME='service_account_smoke',MULTI_DATABASE_USER='fixture',MULTI_DATABASE_PASS='fixture-local-only',
        API_KEY='fixture-legacy-application-key',DEFAULT_API_KEY='fixture-legacy-application-key',CRYPT_KEY='fixture-only',
        DEFAULT_EXTERNAL_DATABASE_USER='forbidden_default_must_never_be_used',DEFAULT_EXTERNAL_DATABASE_PASSWORD='invalid-fixture-default',
        DIRETORIO_URL='http://authority:8080/',APIKEY_VALIDATE_URL='http://authority:8080/',OAUTH_USER_INFO_URL='http://127.0.0.1:9/',
        AUTHORIZATION_API_URL='http://authority:8080/authz-api',SERVICE_ACCOUNT_SYSTEM_ID='664',SERVICE_ACCOUNT_READ_FUNCTIONS='READ',
        SERVICE_ACCOUNT_REDIS_URL='redis://redis:6379/0',AUDIT_REDIS_URL=os.getenv('SERVICE_ACCOUNT_TEST_AUDIT_REDIS_URL',''),AUDIT_STREAM_KEY='audit:requests',AUDIT_SERVICE_NAME=name,SERVICE_ACCOUNT_TRUSTED_PROXIES='',
        MULTIDATABASE_API_URL='http://authority:8080/v1/erp/credentials',SERVICE_ACCOUNT_TOKEN_URL='http://authority:8080/token',
        SERVICE_ACCOUNT_CLIENT_ID=name+'-api',SERVICE_ACCOUNT_CLIENT_SECRET='fixture-client-secret')
    packaged=os.getenv('SERVICE_ACCOUNT_PACKAGED_IMAGES')=='1'
    if packaged: environment['PYTHONPATH']='/var/www/html'
    services[name]=dict(image=name+'-service-accounts:tests' if packaged else 'arquiteturansj/flask:2.2',environment=environment,
        volumes=[] if packaged else [f'{path}:/var/www/html:ro',f'{ROOT.parents[2]}:/shared:ro'],
        ports=[f'127.0.0.1:{port}:80'],entrypoint=['sh','-ec','python3 tools/install-safe-logging.py; exec /entrypoint.sh'])
services['client']['volumes'] += [f'{WORK / (repo + "-contas-servico-dev")}:/workspace/{repo}-contas-servico-dev:ro' for repo in ['Atendimento','ErpApiWeb','estoque-backend','estoque-api','tesouraria-api']]
services['client']['user']=f'{os.getuid()}:{os.getgid()}'
project=dict(name='service-account-consumers',services=services)
(local/'compose.json').write_text(json.dumps(project,indent=2))
print('Prepared isolated five-consumer stack; authority source '+REVISION)
