"""Opt-in ADR-0175 adapter for Flask/Python 3.10 consumers of legacy auth/multidb.

No token exchange of an employee and no default database credentials. Policies are
exact (endpoint, rule, method) registrations; every other route fails closed.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import quote, urljoin

import requests
from flask import g, has_request_context, jsonify, request

from ._service_account_audit import AuditPublisher, events as audit_events, start as audit_start
from ._service_account_errors import AuthError, ForbiddenError, UnauthorizedError
from ._service_account_core import (
    ServiceAccountAuthenticator, ServiceAccountUnavailable, ServiceAccountForbidden, conferir_protecoes,
    ip_do_cliente, user_data_da_conta,
)


def is_authenticated():
    return has_request_context() and g.get('_service_account_authenticated') is True


def multi_database():
    """Use the already authorized account's database; preserve the legacy path for humans."""
    from nsj_multi_database_lib.decorator.multi_database import multi_database as legacy
    def decorate(func):
        normal = legacy()(func)
        @wraps(func)
        def wrapped(*args, **kwargs):
            if is_authenticated():
                if not g.get('external_database') or g.external_database.get('tenant') != g.service_account_tenant:
                    raise ServiceAccountUnavailable('Banco da conta de serviço indisponível.')
                return func(*args, **kwargs)
            return normal(*args, **kwargs)
        return wrapped
    return decorate


def _redact(value):
    from urllib.parse import unquote
    text = str(value)
    decoded = text
    for _ in range(3):
        decoded = unquote(decoded)
    if 'nsa_' not in decoded.lower():
        return text
    return re.sub(r'\bnsa_[A-Za-z0-9_-]+', 'nsa_[REDACTED]', decoded, flags=re.I)


class Redactor(logging.Filter):
    def filter(self, record):
        record.msg = _redact(record.getMessage())
        record.args = ()
        if record.exc_text:
            record.exc_text = _redact(record.exc_text)
        if record.exc_info and 'nsa_' in str(record.exc_info).lower():
            record.exc_info = None
        return True


class ServiceAccountExtension:
    def __init__(self, app, auth, *, routes, system_id, functions, directory_url,
                 application_key, redis=None, transport=None, database=None, target_filters=None, audit=None):
        self.auth = auth
        self.routes = routes
        self.target_filters = target_filters or {}
        self.system_id = str(system_id or '')
        self.functions = set(functions)
        self.directory_url = directory_url or ''
        self.application_key = application_key or ''
        self.redis = redis
        self.audit = audit or AuditPublisher()
        self.http = transport or requests.Session()
        self.database = database or self._database
        self.authority = ServiceAccountAuthenticator(
            lambda: os.getenv('AUTHORIZATION_API_URL'), transporte=self._authority_transport)
        self.profiles = {}
        self.lock = threading.Lock()
        self.token = None
        app.before_request(self.before_request)
        app.after_request(self.after_request)
        for handler in list(logging.getLogger().handlers) + list(logging.getLogger(app.name).handlers) + list(auth._logger.handlers):
            handler.addFilter(Redactor())

    def _authority_transport(self, url, body, headers, timeout):
        try:
            response = self.http.post(url, data=body, headers=headers, timeout=(2, 5), allow_redirects=False)
            return response.status_code, response.content
        except requests.RequestException:
            raise ServiceAccountUnavailable('Autoridade indisponível.') from None

    @staticmethod
    def _attempt():
        values = [*request.headers.getlist('X-API-Key'), *request.headers.getlist('apikey'),
                  *request.headers.getlist('Authorization'), *request.args.getlist('token'), *request.args.getlist('apikey')]
        return any(bool(re.match(r'^(?:Bearer\s+)?nsa_', str(v).strip(), flags=re.I)) for v in values)

    def _credentials(self):
        values = request.headers.getlist('X-API-Key')
        if len(values) != 1 or any(h in request.headers for h in ('Authorization', 'apikey')) \
                or any(k in request.args for k in ('token', 'apikey')) \
                or not re.fullmatch(r'nsa_[A-Za-z0-9]{8}_[A-Za-z0-9_-]{43,128}', values[0]):
            raise UnauthorizedError('Credencial inválida. Use somente X-API-Key.')
        return values[0]

    @staticmethod
    def _validate(account, key):
        try:
            if not (type(account['conta_id']) is int and account['conta_id'] > 0):
                raise ValueError('Contrato inválido.')
            if not (re.fullmatch(r'serv_acc_[a-f0-9]{32}@svc\.nasajon\.app', account['email'])):
                raise ValueError('Contrato inválido.')
            if not isinstance(account['nome'], str):
                raise ValueError('Contrato inválido.')
            if not (type(account['version']) is int and account['version'] > 0):
                raise ValueError('Contrato inválido.')
            if not (account['prefixo'] == key.split('_', 2)[1]):
                raise ValueError('Contrato inválido.')
            if not (account['alcance'] in ('tenant', 'sistema')):
                raise ValueError('Contrato inválido.')
            if not (type(account['tenants']) is list and all(type(t) is int and t > 0 for t in account['tenants'])):
                raise ValueError('Contrato inválido.')
            if account['alcance'] == 'tenant':
                if not (account['tenants'] == [account['tenant']] and type(account['tenant']) is int):
                    raise ValueError('Contrato inválido.')
            else:
                if not (account.get('tenant') is None):
                    raise ValueError('Contrato inválido.')
            protections = account['protecoes']
            if not (type(protections['require_signature']) is bool):
                raise ValueError('Contrato inválido.')
            if not (type(protections['allowed_cidrs']) is list and type(protections['chaves_publicas']) is list):
                raise ValueError('Contrato inválido.')
            identifiers = set()
            for public in protections['chaves_publicas']:
                if not isinstance(public, dict) or not isinstance(public.get('key_id'), str) or not public['key_id'] \
                        or public.get('algorithm') not in ('ed25519', 'ecdsa-p256-sha256') \
                        or not isinstance(public.get('public_key_pem'), str) or public['key_id'] in identifiers:
                    raise ValueError('Contrato inválido.')
                identifiers.add(public['key_id'])
            for cidr in protections['allowed_cidrs']:
                ipaddress.ip_network(cidr, strict=False)
            expires = datetime.fromisoformat(account['expira_em'].replace('Z', '+00:00'))
            if not (expires.tzinfo is not None):
                raise ValueError('Contrato inválido.')
        except (KeyError, TypeError, ValueError, AssertionError):
            raise ServiceAccountUnavailable('Resposta da autoridade fora do contrato.') from None
        if expires <= datetime.now(timezone.utc):
            raise UnauthorizedError('Credencial inválida.')

    def _profile(self, account):
        started = time.monotonic()
        cache_key = (account['conta_id'], account['version'])
        with self.lock:
            cached = self.profiles.get(cache_key)
        if cached and started - cached[0] < 30:
            return copy.deepcopy(cached[1])
        if not self.directory_url or not self.application_key or self.application_key.startswith('nsa_'):
            raise ServiceAccountUnavailable('Perfil indisponível.')
        try:
            response = self.http.get(urljoin(self.directory_url, '/v2/api/profile/' + quote(account['email'], safe='')),
                headers={'apikey': self.application_key}, timeout=(2, 5), allow_redirects=False)
            profile = response.json()
            if not (response.status_code == 200 and str(profile['id']) == str(account['conta_id'])):
                raise ValueError('Contrato inválido.')
            if not (profile['email'].lower() == account['email'].lower() and profile.get('tipo', 'SERVICO') == 'SERVICO'):
                raise ValueError('Contrato inválido.')
            if not (type(profile['tenants']) is list):
                raise ValueError('Contrato inválido.')
        except (requests.RequestException, ValueError, KeyError, TypeError, AssertionError):
            raise ServiceAccountUnavailable('Perfil indisponível.') from None
        with self.lock:
            if len(self.profiles) > 10000:
                self.profiles.clear()
            self.profiles[cache_key] = (started, profile)
        return copy.deepcopy(profile)

    def _authorize(self, account, profile):
        registration = self.routes.get(request.endpoint)
        if not registration or request.method != 'GET' or request.headers.get('X-HTTP-Method-Override') \
                or request.get_data() or request.url_rule.rule != registration:
            raise ForbiddenError('Operação não permitida para conta de serviço.')
        tenants = request.args.getlist('tenant')
        if len(tenants) != 1 or not re.fullmatch(r'[1-9][0-9]*', tenants[0]):
            raise ForbiddenError('Tenant obrigatório e inequívoco.')
        tenant_id = int(tenants[0])
        if tenant_id not in account['tenants']:
            raise ForbiddenError('Tenant não permitido.')
        if 'X-Tenant' in request.headers and request.headers['X-Tenant'] != tenants[0]:
            raise ForbiddenError('Tenant contraditório.')
        # Reviewed routes are tenant-wide reads. Never widen a group/company/site grant.
        for name in ('grupoempresarial', 'grupo_empresarial', 'empresa', 'estabelecimento'):
            if name in request.args and name not in self.target_filters.get(request.endpoint, ()):
                raise ForbiddenError('Escopo não revisado.')
        tenant = next((t for t in profile['tenants'] if str(t.get('id')) == tenants[0]), None)
        if not tenant or not self.system_id or not self.functions:
            raise ForbiddenError('Provisão obrigatória.')
        granted = False
        for system in tenant.get('sistemas', []):
            if str(system.get('id')) != self.system_id or system.get('entidades'):
                continue
            granted = any(f.get('codigo') in self.functions for f in system.get('funcoes', []))
            if granted:
                break
        if not granted:
            raise ForbiddenError('Provisão de consulta obrigatória.')
        profile['tenants'] = [tenant]
        tenant['administrador'] = False
        return tenant_id

    def _redis(self):
        if self.redis is None and os.getenv('SERVICE_ACCOUNT_REDIS_URL'):
            import redis
            self.redis = redis.Redis.from_url(os.environ['SERVICE_ACCOUNT_REDIS_URL'], socket_timeout=1, socket_connect_timeout=1)
        return self.redis

    def before_request(self):
        if not self._attempt():
            return None
        g._service_account_attempt = True
        g._service_account_audit = audit_start()
        try:
            key = self._credentials()
            account = self.authority.autenticar(key)
            self._validate(account, key)  # Includes expiration on every cache hit.
            g.service_account = {k: account.get(k) for k in ('conta_id', 'email', 'prefixo', 'version', 'tenant')}
            raw_uri = request.environ.get('RAW_URI') or request.environ.get('REQUEST_URI')
            if not raw_uri:
                raw_uri = request.path + ('?' + request.query_string.decode('ascii') if request.query_string else '')
            if account['protecoes']['require_signature'] and 'X-Tenant' in request.headers:
                signature_input = request.headers.get('Signature-Input', '')
                components = signature_input.split(')', 1)[0]
                if '"x-tenant"' not in components:
                    raise ServiceAccountForbidden('Assinatura deve cobrir X-Tenant.', motivo='assinatura')
            conferir_protecoes(account, ip=ip_do_cliente(request.headers, request.environ.get('REMOTE_ADDR')),
                metodo=request.method, caminho=raw_uri, cabecalhos=request.headers, corpo=request.get_data(), redis=self._redis())
            profile = self._profile(account)
            tenant = self._authorize(account, profile)
            database = self.database(account, tenant)
            g.external_database = database
            g.service_account_tenant = tenant
            g.profile = {'nome': account.get('nome'), 'email': account['email'], 'user_profile': profile,
                         'authentication_type': 'access_token', 'service_account': g.service_account}
            g.user_data = user_data_da_conta(account)
            g._service_account_authenticated = True
        except AuthError as error:
            g._service_account_reason = getattr(error, 'motivo', 'permissao')
            status = error.status_code
            response = jsonify(message=str(error))
            response.status_code = status
            if status == 503:
                response.headers['Retry-After'] = '1'
            return response

    def _database(self, account, tenant):
        """D8: only the API client token reaches Multidb; never the incoming key."""
        token_url = os.getenv('SERVICE_ACCOUNT_TOKEN_URL', '')
        client = os.getenv('SERVICE_ACCOUNT_CLIENT_ID', '')
        secret = os.getenv('SERVICE_ACCOUNT_CLIENT_SECRET', '')
        url = os.getenv('MULTIDATABASE_API_URL', '')
        if not all((token_url, client, secret, url)):
            raise ServiceAccountUnavailable('Credencial de banco da conta de serviço indisponível.')
        try:
            with self.lock:
                if not self.token or self.token[0] <= time.monotonic():
                    result = self.http.post(token_url, data={'grant_type': 'client_credentials', 'audience': 'nsj-multidb-api'},
                        auth=(client, secret), timeout=(2, 5), allow_redirects=False)
                    data = result.json()
                    if not (result.status_code == 200 and data['token_type'].lower() == 'bearer'):
                        raise ValueError('Contrato inválido.')
                    if not (isinstance(data['access_token'], str) and data['access_token']):
                        raise ValueError('Contrato inválido.')
                    ttl = min(int(data['expires_in']), 300) - 10
                    if not (ttl > 0):
                        raise ValueError('Contrato inválido.')
                    self.token = (time.monotonic() + ttl, data['access_token'])
                token = self.token[1]
            result = self.http.get(url, params={'tenant': tenant, 'service_account': account['email']},
                headers={'Authorization': 'Bearer ' + token}, timeout=(2, 5), allow_redirects=False)
            data = result.json()
            if result.status_code in (401, 403):
                raise ForbiddenError('Banco não autorizado para a conta de serviço.')
            if not (result.status_code == 200 and not data.get('role')):
                raise ValueError('Contrato inválido.')
            if not (all(isinstance(data[k], str) and data[k] for k in ('hostname', 'db_name', 'user', 'password'))):
                raise ValueError('Contrato inválido.')
            if not (0 < int(data['port']) <= 65535):
                raise ValueError('Contrato inválido.')
        except (requests.RequestException, ValueError, KeyError, TypeError, AssertionError):
            raise ServiceAccountUnavailable('Credencial de banco indisponível.') from None
        return {'host': data['hostname'], 'port': data['port'], 'name': data['db_name'],
                'user': data['user'], 'password': data['password'], 'tenant': tenant, 'user_id': data.get('user_id')}

    def after_request(self, response):
        snapshot = g.get('_service_account_audit')
        if snapshot and not snapshot.get('finished') and not g.get('_service_account_audit_native'):
            snapshot['finished'] = True
            account = g.get('service_account')
            tenant = g.get('service_account_tenant') or (account or {}).get('tenant')
            pair = audit_events(snapshot, account=account, tenant=tenant,
                route=request.endpoint, method=request.method, status=response.status_code,
                reason=g.get('_service_account_reason'), application=os.getenv('AUDIT_SERVICE_NAME', 'flask-api'))
            self.audit.publish(pair[-1:] if g.get('_service_account_audit_native_started') else pair)
        account = g.get('service_account')
        if account:
            self.auth._logger.info('service_account.request %s', json.dumps({
                'source_system': 'sa_' + str(account['conta_id']), 'actor_user_id': account['email'],
                'prefixo': account['prefixo'], 'version': account['version'],
                'endpoint': request.endpoint, 'method': request.method, 'status': response.status_code}))
        return response
