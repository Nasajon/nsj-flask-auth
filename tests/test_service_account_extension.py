import base64
import copy
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from flask import Flask, g, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from nsj_flask_auth.service_accounts import ServiceAccountExtension, is_authenticated, Redactor

KEY = 'nsa_Abcd1234_' + 's' * 43
EMAIL = 'serv_acc_' + 'a' * 32 + '@svc.nasajon.app'


def account():
    return dict(conta_id=77, email=EMAIL, nome='Integration', alcance='tenant', tenant=47,
        tenants=[47], prefixo='Abcd1234', version=2,
        expira_em=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        protecoes=dict(require_signature=False, allowed_cidrs=[], chaves_publicas=[]))


def profile():
    return dict(id=77, email=EMAIL, tipo='SERVICO', tenants=[dict(id=47, codigo='fixture', administrador=True,
        sistemas=[dict(id=664, entidades=[], funcoes=[dict(codigo='READ')])])])


class Response:
    def __init__(self, data, status=200):
        self.status_code = status
        self.content = json.dumps(data).encode()
        self.data = data
    def json(self):
        return copy.deepcopy(self.data)


class Transport:
    def __init__(self):
        self.account = account()
        self.profile = profile()
        self.status = 200
        self.calls = []
    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        assert url == 'http://authority/authz-api/service-accounts/authenticate'
        assert kwargs['allow_redirects'] is False and kwargs['timeout'] == (2, 5)
        return Response(self.account, self.status)
    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        assert kwargs['headers'] == {'apikey': 'legacy-application-key'}
        assert KEY not in str((url, kwargs))
        return Response(self.profile)


class Nonces:
    def __init__(self): self.keys = set()
    def set(self, key, value, **kwargs):
        assert kwargs == {'nx': True, 'ex': 600}
        if key in self.keys: return False
        self.keys.add(key)
        return True
    def hincrby(self, *args): pass
    def expire(self, *args): pass
    def hset(self, *args): pass


@pytest.fixture
def setup(monkeypatch):
    monkeypatch.setenv('AUTHORIZATION_API_URL', 'http://authority/authz-api')
    monkeypatch.delenv('SERVICE_ACCOUNT_REDIS_URL', raising=False)
    monkeypatch.delenv('SERVICE_ACCOUNT_TRUSTED_PROXIES', raising=False)
    monkeypatch.delenv('MULTIDATABASE_API_URL', raising=False)
    app = Flask(__name__)
    auth = SimpleNamespace(_logger=logging.getLogger('fixture.service_accounts'))
    transport = Transport()
    hits = []
    databases = []
    def database(a, tenant):
        databases.append((a['conta_id'], tenant))
        return {'host': 'local', 'port': 5432, 'name': 'test', 'user': 'sa', 'password': 'fixture', 'tenant': tenant}
    extension = ServiceAccountExtension(app, auth, routes={'read': '/read'}, system_id=664,
        functions=['READ'], directory_url='http://directory/', application_key='legacy-application-key',
        transport=transport, database=database, redis=Nonces())
    @app.route('/read', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
    def read():
        hits.append('read')
        if not is_authenticated(): return jsonify(human=True)
        assert g.external_database['tenant'] == 47
        assert g.profile['user_profile']['tenants'][0]['administrador'] is False
        return jsonify(actor=g.profile['email'], source_system='sa_77')
    @app.route('/employee')
    def employee():
        hits.append('employee')
        raise AssertionError('Employee route must never run')
    return app.test_client(), extension, transport, hits, databases


def test_read_without_impersonation_and_cached_authority(setup):
    client, extension, http, hits, databases = setup
    for _ in range(2):
        response = client.get('/read?tenant=47', headers={'X-API-Key': KEY})
        assert response.status_code == 200
        assert response.json == dict(actor=EMAIL, source_system='sa_77')
        assert 'Set-Cookie' not in response.headers
    assert len(http.calls) == 2
    assert databases == [(77, 47), (77, 47)]
    assert KEY not in str(extension.authority._cache)


@pytest.mark.parametrize('headers,query', [
    ({'Authorization': 'Bearer ' + KEY}, ''), ({'Authorization': 'bearer ' + KEY}, ''),
    ({'apikey': KEY}, ''), ({}, 'apikey=' + KEY), ({}, 'token=' + KEY),
    ({'X-API-Key': KEY, 'Authorization': 'Bearer human'}, ''),
    ({'X-API-Key': KEY, 'apikey': 'legacy'}, ''),
    ({'X-API-Key': KEY}, 'token=human'),
    ({'X-API-Key': KEY + ',' + KEY}, ''), ({'X-API-Key': ' ' + KEY}, ''),
    ({'X-API-Key': 'nsa_bad_short'}, ''),
    ({'X-API-Key': KEY.replace('nsa_', 'NSA_', 1)}, ''),
    ({'Authorization': 'Bearer ' + KEY.replace('nsa_', 'NSA_', 1)}, ''),
])
def test_wrong_transport_is_rejected_before_any_remote_call(setup, headers, query):
    client, extension, http, hits, databases = setup
    response = client.get('/read?tenant=47&' + query, headers=headers)
    assert response.status_code == 401
    assert not hits and not databases and not http.calls
    assert KEY not in response.get_data(as_text=True)


@pytest.mark.parametrize('path,method,headers,body', [
    ('/employee?tenant=47', 'GET', {}, None), ('/read?tenant=48', 'GET', {}, None),
    ('/read', 'GET', {}, None), ('/read?tenant=47&tenant=48', 'GET', {}, None),
    ('/read?tenant=047', 'GET', {}, None), ('/read?tenant=47', 'HEAD', {}, None),
    ('/read?tenant=47', 'POST', {}, None), ('/read?tenant=47', 'PUT', {}, None),
    ('/read?tenant=47', 'PATCH', {}, None), ('/read?tenant=47', 'DELETE', {}, None),
    ('/read?tenant=47', 'GET', {}, b'{}'),
    ('/read?tenant=47', 'GET', {'X-Tenant': '48'}, None),
    ('/read?tenant=47', 'GET', {'X-HTTP-Method-Override': 'POST'}, None),
    ('/read?tenant=47&grupo_empresarial=G', 'GET', {}, None),
    ('/read?tenant=47&empresa=C', 'GET', {}, None),
    ('/read?tenant=47&estabelecimento=S', 'GET', {}, None),
])
def test_route_method_and_scope_are_closed_before_database(setup, path, method, headers, body):
    client, extension, http, hits, databases = setup
    response = client.open(path, method=method, headers={'X-API-Key': KEY, **headers}, data=body)
    assert response.status_code == 403
    assert not hits and not databases


@pytest.mark.parametrize('change', [
    lambda p: p.update(id=78), lambda p: p.update(email='human@example.org'),
    lambda p: p.update(tipo='HUMANA'), lambda p: p.update(tenants=None),
])
def test_profile_identity_is_bound_to_authority(setup, change):
    client, extension, http, hits, databases = setup
    change(http.profile)
    assert client.get('/read?tenant=47', headers={'X-API-Key': KEY}).status_code == 503
    assert not hits and not databases


@pytest.mark.parametrize('change', [
    lambda a: a.update(conta_id=True), lambda a: a.update(version=0),
    lambda a: a.update(email='human@example.org'), lambda a: a.update(prefixo='Other123'),
    lambda a: a.update(tenants=[47, 48]), lambda a: a.update(tenants=['47']),
    lambda a: a['protecoes'].update(require_signature='false'),
    lambda a: a['protecoes'].update(allowed_cidrs=['bad/cidr']),
    lambda a: a.update(expira_em='bad'),
    lambda a: a.update(nome=None),
    lambda a: a['protecoes'].update(chaves_publicas=[{}]),
    lambda a: a['protecoes'].update(chaves_publicas=[dict(key_id='x',algorithm='bad',public_key_pem='x')]),
])
def test_authority_contract_is_validated(setup, change):
    client, extension, http, hits, databases = setup
    change(http.account)
    assert client.get('/read?tenant=47', headers={'X-API-Key': KEY}).status_code == 503
    assert not hits and not databases


@pytest.mark.parametrize('status,expected', [(401, 401), (403, 401), (302, 503), (429, 503), (500, 503), (503, 503)])
def test_authority_failure_has_no_fallback(setup, status, expected):
    client, extension, http, hits, databases = setup
    http.status = status
    assert client.get('/read?tenant=47', headers={'X-API-Key': KEY}).status_code == expected
    assert len(http.calls) == 1 and not hits and not databases


@pytest.mark.parametrize('change', [
    lambda p: p['tenants'][0]['sistemas'][0].update(funcoes=[]),
    lambda p: p['tenants'][0]['sistemas'][0].update(id=665),
    lambda p: p['tenants'][0]['sistemas'][0].update(entidades={'empresa': ['C']}),
    lambda p: p['tenants'][0].update(sistemas=[]),
    lambda p: p['tenants'][0].update(id=48),
])
def test_admin_flag_never_replaces_a_positive_unrestricted_provision(setup, change):
    client, extension, http, hits, databases = setup
    change(http.profile)
    assert client.get('/read?tenant=47', headers={'X-API-Key': KEY}).status_code == 403
    assert not hits and not databases


def test_expiration_is_checked_on_cache_hits(setup):
    client, extension, http, hits, databases = setup
    assert client.get('/read?tenant=47', headers={'X-API-Key': KEY}).status_code == 200
    cached = next(iter(extension.authority._cache.values()))[1]
    cached['expira_em'] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    assert client.get('/read?tenant=47', headers={'X-API-Key': KEY}).status_code == 401
    assert len(hits) == 1


def test_fake_proxy_header_does_not_bypass_ip_policy(setup):
    client, extension, http, hits, databases = setup
    http.account['protecoes']['allowed_cidrs'] = ['203.0.113.0/24']
    assert client.get('/read?tenant=47', headers={'X-API-Key': KEY, 'X-Real-IP': '203.0.113.1'}).status_code == 403
    assert not hits and not databases


def signed_headers(private, algorithm, *, tenant='47', cover_tenant=True, nonce='nonce-12345678'):
    fields = ['@method', '@path', '@query'] + (['x-tenant'] if cover_tenant else [])
    components = ' '.join('"' + c + '"' for c in fields)
    params = f'({components});created={int(time.time())};nonce="{nonce}";keyid="test";alg="{algorithm}"'
    values = {'@method': 'GET', '@path': '/read', '@query': '?tenant=47', 'x-tenant': tenant}
    lines = [f'"{c}": {values[c]}' for c in fields] + ['"@signature-params": ' + params]
    data = '\n'.join(lines).encode()
    if algorithm == 'ed25519': signature = private.sign(data)
    else:
        from cryptography.hazmat.primitives import hashes
        r, s = decode_dss_signature(private.sign(data, ec.ECDSA(hashes.SHA256())))
        signature = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    return {'X-API-Key': KEY, 'X-Tenant': tenant, 'Signature-Input': 'sig1=' + params,
            'Signature': 'sig1=:' + base64.b64encode(signature).decode() + ':'}


@pytest.mark.parametrize('algorithm', ['ed25519', 'ecdsa-p256-sha256'])
def test_real_crypto_replay_and_signed_tenant(setup, algorithm):
    client, extension, http, hits, databases = setup
    private = ed25519.Ed25519PrivateKey.generate() if algorithm == 'ed25519' else ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    http.account['protecoes'].update(require_signature=True, chaves_publicas=[dict(key_id='test', algorithm=algorithm, public_key_pem=public)])
    headers = signed_headers(private, algorithm)
    assert client.get('/read?tenant=47', headers=headers).status_code == 200
    assert client.get('/read?tenant=47', headers=headers).status_code == 403
    headers = signed_headers(private, algorithm, cover_tenant=False, nonce='nonce-unsigned-tenant')
    assert client.get('/read?tenant=47', headers=headers).status_code == 403
    headers = signed_headers(private, algorithm, nonce='nonce-tampered-tenant')
    headers['X-Tenant'] = '48'
    assert client.get('/read?tenant=47', headers=headers).status_code == 403
    assert len(hits) == 1 and len(databases) == 1


def test_signature_without_redis_fails_closed(setup):
    client, extension, http, hits, databases = setup
    private = ed25519.Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    http.account['protecoes'].update(require_signature=True, chaves_publicas=[dict(key_id='test', algorithm='ed25519', public_key_pem=public)])
    extension.redis = None
    assert client.get('/read?tenant=47', headers=signed_headers(private, 'ed25519')).status_code == 503
    assert not hits and not databases


def test_no_default_database_fallback_without_client_credentials(setup):
    client, extension, http, hits, databases = setup
    extension.database = extension._database
    assert client.get('/read?tenant=47', headers={'X-API-Key': KEY}).status_code == 503
    assert not hits and not databases


def test_human_requests_keep_the_original_path(setup):
    client, extension, http, hits, databases = setup
    assert client.get('/read?tenant=47', headers={'Authorization': 'Bearer human'}).json == {'human': True}
    assert not http.calls and not databases


def test_redaction_including_encoded_secrets():
    from urllib.parse import quote
    record = logging.LogRecord('test', 20, '', 1, 'URI %s', (quote(quote(KEY)),), None)
    assert Redactor().filter(record)
    assert KEY not in record.getMessage() and '[REDACTED]' in record.getMessage()


def test_target_filter_requires_review_and_whole_tenant_grant(setup):
    client, extension, http, hits, databases = setup
    extension.target_filters = {'read': ('estabelecimento',)}
    assert client.get('/read?tenant=47&estabelecimento=target', headers={'X-API-Key': KEY}).status_code == 200
    extension.profiles.clear()
    http.profile['tenants'][0]['sistemas'][0]['entidades'] = {'estabelecimento': ['target']}
    assert client.get('/read?tenant=47&estabelecimento=target', headers={'X-API-Key': KEY}).status_code == 403
    assert len(hits) == 1


@pytest.mark.parametrize('role,status,expected', [(None,200,200), ('proxy',200,503), (None,403,403), (None,500,503)])
def test_multidb_uses_only_api_client_credentials_without_fallback(setup, monkeypatch, role, status, expected):
    client, extension, http, hits, databases = setup
    for key,value in dict(SERVICE_ACCOUNT_TOKEN_URL='http://token',SERVICE_ACCOUNT_CLIENT_ID='api',SERVICE_ACCOUNT_CLIENT_SECRET='secret',MULTIDATABASE_API_URL='http://multidb').items():monkeypatch.setenv(key,value)
    extension.database = extension._database
    original_post, original_get = http.post, http.get
    calls=[]
    def post(url, **kwargs):
        if url != 'http://token': return original_post(url, **kwargs)
        assert kwargs['auth'] == ('api','secret') and kwargs['data'] == {'grant_type':'client_credentials','audience':'nsj-multidb-api'}
        assert KEY not in str(kwargs)
        calls.append('token')
        return Response(dict(access_token='api-token',token_type='Bearer',expires_in=300))
    def get(url, **kwargs):
        if url != 'http://multidb': return original_get(url, **kwargs)
        assert kwargs['headers'] == {'Authorization':'Bearer api-token'}
        assert kwargs['params'] == {'tenant':47,'service_account':EMAIL} and KEY not in str(kwargs)
        calls.append('multidb')
        return Response(dict(hostname='db',db_name='tenant47',user='sa_77',password='own-secret',port=5432,role=role),status)
    http.post, http.get = post,get
    assert client.get('/read?tenant=47',headers={'X-API-Key':KEY}).status_code == expected
    assert calls == ['token','multidb']
    assert len(hits) == (1 if expected == 200 else 0) and not databases
