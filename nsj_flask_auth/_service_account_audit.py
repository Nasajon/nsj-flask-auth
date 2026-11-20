"""Canonical audit:requests protocol for legacy consumers (Python 3.10+).

No query, body, credential, IP or unverified identity is copied to the event.
Aggregation belongs to auditoria; the nonce Redis is never used for telemetry.
"""
from datetime import datetime, timezone
import json
import logging
import os
import time
import uuid


def start():
    return {'id': str(uuid.uuid4()), 'wall': time.time(), 'clock': time.monotonic()}


def timestamp(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec='milliseconds')


def events(snapshot, *, account, tenant, route, method, status, reason, application):
    account = account or {}
    tenant = tenant if type(tenant) is int and tenant > 0 else 0
    reason = reason if reason in {'chave','ip','assinatura','permissao','autoridade','perfil','redis'} else (
        'chave' if status == 401 else 'permissao' if status == 403 else '')
    identity = dict(conta_id=str(account.get('conta_id', '')), prefixo=account.get('prefixo', ''),
        version=account.get('version', 0), authenticated=bool(account), reason=reason)
    first = dict(event_id=str(uuid.uuid4()), event_type='request_started', event_ts_utc=timestamp(snapshot['wall']),
        request_id=snapshot['id'], tenant_id=str(tenant), grupo_empresarial_id='', area_atendimento_id='',
        db_key='sa_boundary', db_user='', actor_user_id=account.get('email', ''), subject_user_id='', session_id='',
        http_method=method, http_route=route or 'unmatched', action='service_account.request',
        params_normalizados=json.dumps(dict(service_account=identity, application=application), separators=(',', ':')),
        source_system='sa_' + str(account['conta_id']) if account else 'sa_unverified', is_transaction_intent='0')
    last = dict(event_id=str(uuid.uuid4()), event_type='request_finished', event_ts_utc=timestamp(time.time()),
        request_id=snapshot['id'], tenant_id=str(tenant), grupo_empresarial_id='', area_atendimento_id='',
        http_status=str(status), duration_ms=str(max(0, int((time.monotonic()-snapshot['clock'])*1000))),
        tx_attempted='0', is_transaction_intent='0')
    if reason and status >= 400:
        last['error_code'] = 'service_account.' + reason
    return first, last


class AuditPublisher:
    def __init__(self, redis=None):
        self.redis = redis
        self.down_until = 0
        self.disabled_warned = False

    def publish(self, pair):
        if time.monotonic() < self.down_until:
            return
        url = os.getenv('AUDIT_REDIS_URL', '')
        if self.redis is None and not url:
            if not self.disabled_warned:
                logging.getLogger(__name__).info('Service-account audit disabled: AUDIT_REDIS_URL absent')
                self.disabled_warned = True
            return
        try:
            if self.redis is None:
                import redis
                self.redis = redis.Redis.from_url(url, socket_connect_timeout=0.05, socket_timeout=0.05)
            for event in pair:
                self.redis.xadd(os.getenv('AUDIT_STREAM_KEY', 'audit:requests'), event)
        except Exception:
            logging.getLogger(__name__).warning("Service-account audit delivery failed; retry delayed")
            self.redis = None
            self.down_until = time.monotonic() + 30
