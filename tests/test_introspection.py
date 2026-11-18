# pylint: disable=C0114, C0115, C0116
"""Introspection do access token e checagem do client que o emitiu (sem rede: requests mockado)."""

import time
import unittest
from unittest.mock import MagicMock, patch

from flask import Flask, g

from nsj_flask_auth import AccessTokenValidation, Auth
from nsj_flask_auth.exceptions import Forbidden, InternalUnauthorized, Unauthorized

_APP = Flask(__name__)
_INTROSPECT_URL = "https://idp/realms/x/protocol/openid-connect/token/introspect"
_PROFILE = {"email": "ana@x.com", "tenants": [{"id": 47, "codigo": "acme"}]}


def _resp(status=200, body=None):
    response = MagicMock()
    response.status_code = status
    response.json.return_value = body if body is not None else {}
    response.content = b""
    return response


def _claims(**extra):
    claims = {
        "active": True,
        "email": "ana@x.com",
        "name": "Ana",
        "azp": "canal-chat-front",
        "exp": time.time() + 300,
    }
    claims.update(extra)
    return claims


class _DictCache:
    def __init__(self):
        self.data = {}

    def get(self, key):
        return self.data.get(key)

    def set(self, key, value):
        self.data[key] = value


def _auth(**kwargs):
    params = {
        "diretorio_base_uri": "https://dir",
        "profile_uri": "https://idp/userinfo",
        "diretorio_api_key": "k",
        "introspect_url": _INTROSPECT_URL,
        "introspect_token": "Y2xpZW50OnNlY3JldA==",
        "access_token_validation": AccessTokenValidation.INTROSPECTION,
    }
    params.update(kwargs)
    return Auth(**params)


class ConstrucaoTests(unittest.TestCase):
    def test_padrao_continua_userinfo_sem_checagem_de_client(self):
        auth = Auth("https://dir", "https://idp/userinfo", "k")
        with patch("nsj_flask_auth.auth.requests.get", return_value=_resp(body={"email": "a@x"})) as get, patch(
            "nsj_flask_auth.auth.requests.post"
        ) as post:
            self.assertEqual(auth._get_user_profile("Bearer t")["email"], "a@x")
        get.assert_called_once()
        post.assert_not_called()

    def test_introspection_sem_url_ou_credencial_falha_na_construcao(self):
        with self.assertRaises(ValueError):
            _auth(introspect_token=None)

    def test_allowed_client_ids_sem_introspection_falha_na_construcao(self):
        with self.assertRaises(ValueError):
            Auth("https://dir", "https://idp/userinfo", "k", allowed_client_ids=["a"])

    def test_allowed_client_ids_no_decorator_sem_introspection_falha_ao_decorar(self):
        auth = Auth("https://dir", "https://idp/userinfo", "k")
        with self.assertRaises(ValueError):
            auth.requires_api_key_or_access_token(allowed_client_ids=["a"])


class IntrospectionTests(unittest.TestCase):
    def test_token_ativo_devolve_claims_e_manda_credencial_basic(self):
        auth = _auth()
        with patch("nsj_flask_auth.auth.requests.post", return_value=_resp(body=_claims())) as post:
            claims = auth._get_user_profile("Bearer tok")
        self.assertEqual(claims["email"], "ana@x.com")
        _, kwargs = post.call_args
        self.assertEqual(post.call_args[0][0], _INTROSPECT_URL)
        self.assertEqual(kwargs["headers"]["Authorization"], "Basic Y2xpZW50OnNlY3JldA==")
        self.assertEqual(kwargs["data"]["token"], "tok")

    def test_token_inativo_e_401(self):
        auth = _auth()
        with patch("nsj_flask_auth.auth.requests.post", return_value=_resp(body={"active": False})):
            with self.assertRaises(Unauthorized):
                auth._get_user_profile("Bearer tok")

    def test_credencial_da_aplicacao_recusada_e_erro_interno(self):
        auth = _auth()
        with patch("nsj_flask_auth.auth.requests.post", return_value=_resp(status=401)):
            with self.assertRaises(InternalUnauthorized):
                auth._get_user_profile("Bearer tok")

    def test_cache_so_guarda_token_ativo_e_expira_com_o_token(self):
        cache = _DictCache()
        auth = _auth(caching_service=cache)
        with patch("nsj_flask_auth.auth.requests.post", return_value=_resp(body=_claims())) as post:
            auth._get_user_profile("Bearer tok")
            auth._get_user_profile("Bearer tok")
        self.assertEqual(post.call_count, 1)

        # Entrada de cache de um token já expirado não vale: volta ao IdP.
        for key in list(cache.data):
            cache.data[key] = _claims(exp=time.time() - 1)
        with patch("nsj_flask_auth.auth.requests.post", return_value=_resp(body={"active": False})):
            with self.assertRaises(Unauthorized):
                auth._get_user_profile("Bearer tok")


class ClientEsperadoTests(unittest.TestCase):
    def test_client_fora_da_lista_e_403(self):
        auth = _auth(allowed_client_ids=["canal-chat-front"])
        with patch("nsj_flask_auth.auth.requests.post", return_value=_resp(body=_claims(azp="outro-app"))):
            with self.assertRaises(Forbidden):
                auth._get_user_profile("Bearer tok")

    def test_client_da_lista_passa_e_lista_aceita_string_separada_por_virgula(self):
        auth = _auth(allowed_client_ids="painel-cliente, canal-chat-front")
        with patch("nsj_flask_auth.auth.requests.post", return_value=_resp(body=_claims())):
            self.assertEqual(auth._get_user_profile("Bearer tok")["azp"], "canal-chat-front")

    def test_usa_client_id_quando_nao_ha_azp(self):
        auth = _auth(allowed_client_ids=["svc"])
        body = _claims(azp=None, client_id="svc")
        with patch("nsj_flask_auth.auth.requests.post", return_value=_resp(body=body)):
            auth._get_user_profile("Bearer tok")

    def test_checagem_vale_tambem_em_cache_hit(self):
        cache = _DictCache()
        auth = _auth(caching_service=cache)
        with patch("nsj_flask_auth.auth.requests.post", return_value=_resp(body=_claims(azp="outro-app"))):
            auth._get_user_profile("Bearer tok")  # sem lista na construção: passa e vai pro cache
            with self.assertRaises(Forbidden):
                auth._get_user_profile("Bearer tok", ["canal-chat-front"])

    def test_decorator_sobrescreve_lista_da_construcao(self):
        auth = _auth(allowed_client_ids=["canal-chat-front"])

        @auth.requires_api_key_or_access_token(allowed_client_ids=["painel-cliente"])
        def view():
            return "ok"

        with patch("nsj_flask_auth.auth.requests.post", return_value=_resp(body=_claims(azp="painel-cliente"))), patch.object(
            auth, "_get_user_profile_vendor", return_value=_PROFILE
        ):
            with _APP.test_request_context(headers={"Authorization": "Bearer tok"}):
                self.assertEqual(view(), "ok")
                self.assertEqual(g.profile["email"], "ana@x.com")

        with patch("nsj_flask_auth.auth.requests.post", return_value=_resp(body=_claims())), patch.object(
            auth, "_get_user_profile_vendor", return_value=_PROFILE
        ):
            with _APP.test_request_context(headers={"Authorization": "Bearer tok"}):
                body, status, _ = view()
        self.assertEqual(status, 403)


class EscopoDeTenantTests(unittest.TestCase):
    def _view(self, auth):
        @auth.requires_api_key_or_access_token()
        def view():
            return "ok"

        return view

    def test_post_multipart_nao_quebra_a_autenticacao(self):
        auth = _auth()
        view = self._view(auth)
        with patch("nsj_flask_auth.auth.requests.post", return_value=_resp(body=_claims())), patch.object(
            auth, "_get_user_profile_vendor", return_value=_PROFILE
        ):
            with _APP.test_request_context(
                method="POST",
                headers={"Authorization": "Bearer tok"},
                data={"arquivo": "x"},
                content_type="multipart/form-data",
            ):
                self.assertEqual(view(), "ok")

    def test_tenant_na_query_aceita_codigo_do_tenant(self):
        auth = _auth()
        view = self._view(auth)
        with patch("nsj_flask_auth.auth.requests.post", return_value=_resp(body=_claims())), patch.object(
            auth, "_get_user_profile_vendor", return_value=_PROFILE
        ):
            with _APP.test_request_context("/?tenant=acme", headers={"Authorization": "Bearer tok"}):
                self.assertEqual(view(), "ok")
            with _APP.test_request_context("/?tenant=outro", headers={"Authorization": "Bearer tok"}):
                self.assertEqual(view()[1], 403)


if __name__ == "__main__":
    unittest.main()
