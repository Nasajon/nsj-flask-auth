import json
import uuid

import pytest

from nsj_flask_auth._service_account_audit import AuditPublisher, events, start
from tests.test_service_account_extension import setup, KEY


class Capture:
    def __init__(self): self.pairs = []
    def publish(self, pair): self.pairs.append(pair)


@pytest.mark.parametrize('path,headers,expected,verified', [
    ('/read?tenant=47', {'X-API-Key': KEY}, 200, True),
    ('/read?tenant=48', {'X-API-Key': KEY}, 403, True),
    ('/employee?tenant=47', {'X-API-Key': KEY}, 403, True),
    ('/read?tenant=47', {'Authorization': 'Bearer ' + KEY}, 401, False),
    ('/read?tenant=47&apikey=' + KEY, {}, 401, False),
])
def test_canonical_pair_covers_success_and_pre_controller_refusals(setup, path, headers, expected, verified):
    client, extension, http, hits, databases = setup
    extension.audit = capture = Capture()
    assert client.get(path, headers=headers).status_code == expected
    assert len(capture.pairs) == 1
    first, last = capture.pairs[0]
    uuid.UUID(first['event_id']); uuid.UUID(last['event_id']); uuid.UUID(first['request_id'])
    assert first['request_id'] == last['request_id']
    assert first['event_type'] == 'request_started' and last['event_type'] == 'request_finished'
    assert last['http_status'] == str(expected)
    params = json.loads(first['params_normalizados'])
    assert params['service_account']['authenticated'] is verified
    assert first['source_system'] == ('sa_77' if verified else 'sa_unverified')
    assert first['tenant_id'] == ('47' if verified else '0')
    assert first['is_transaction_intent'] == last['tx_attempted'] == '0'
    assert KEY not in json.dumps(capture.pairs)
    assert 'tenant=48' not in json.dumps(capture.pairs)
    if expected != 200: assert not hits


def test_authority_outage_is_audited_without_attributing_the_account(setup):
    client, extension, http, hits, databases = setup
    extension.audit = capture = Capture(); http.status = 503
    assert client.get('/read?tenant=47', headers={'X-API-Key': KEY}).status_code == 503
    first, last = capture.pairs[0]
    assert first['source_system'] == 'sa_unverified' and last['http_status'] == '503'
    assert not hits and not databases


def test_human_request_does_not_create_a_service_account_event(setup):
    client, extension, http, hits, databases = setup
    extension.audit = capture = Capture()
    assert client.get('/read?tenant=47').status_code == 200
    assert not capture.pairs


def test_audit_transport_uses_its_own_stream_and_never_usage_hashes(monkeypatch):
    class Redis:
        def __init__(self): self.events = []
        def xadd(self, name, fields): self.events.append((name, fields))
    monkeypatch.setenv('AUDIT_STREAM_KEY', 'audit:requests')
    redis = Redis()
    publisher = AuditPublisher(redis)
    pair = events(start(), account=None, tenant=None, route='read', method='GET', status=401,
        reason='chave', application='fixture')
    publisher.publish(pair)
    assert redis.events == [('audit:requests', pair[0]), ('audit:requests', pair[1])]


def test_audit_outage_opens_a_circuit_without_affecting_the_caller():
    class Down:
        calls = 0
        def xadd(self, *args):
            self.calls += 1
            raise OSError('Fixture outage')
    redis = Down(); publisher = AuditPublisher(redis)
    pair = events(start(), account=None, tenant=47, route='read', method='GET', status=503,
        reason='redis', application='fixture')
    publisher.publish(pair); publisher.publish(pair)
    assert redis.calls == 1


def test_events_do_not_trust_an_unverified_tenant():
    pair = events(start(), account=None, tenant='forged', route='read', method='GET', status=401,
        reason='injected secret', application='fixture')
    assert pair[0]['tenant_id'] == '0'
    assert pair[1]['error_code'] == 'service_account.chave'
    assert 'injected secret' not in json.dumps(pair)

@pytest.mark.parametrize('environment', ['dev', 'qa'])
def test_optional_audit_does_not_create_a_transport(monkeypatch, setup, environment):
    monkeypatch.setenv('ENV', environment)
    monkeypatch.delenv('AUDIT_REDIS_URL', raising=False)
    import redis
    factory = __import__('unittest.mock', fromlist=['Mock']).Mock()
    monkeypatch.setattr(redis.Redis, 'from_url', factory)
    client, extension, _, hits, _ = setup
    extension.audit = AuditPublisher()
    assert client.get('/read?tenant=47', headers={'X-API-Key':KEY}).status_code == 200
    assert client.get('/employee?tenant=47', headers={'X-API-Key':KEY}).status_code == 403
    assert not factory.called
    assert len(hits) == 1
