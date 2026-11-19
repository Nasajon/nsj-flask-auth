"""Service account por chave de API (ADR-0175-RD01, D4 a D7), agnostico de framework.

A chave `nsa_<prefixo8>_<segredo>` chega no `X-API-Key`. Quem diz de quem ela e' e' a
erp4-authorization-api (`POST {AUTHORIZATION_API_URL}/service-accounts/authenticate`); a resposta fica em
cache por ate' 30 segundos, pela chave inteira em digest (D6: o prazo de revogacao e' o do cache).

As protecoes da D5 dependem da requisicao original, e por isso sao conferidas aqui, no servico que a
recebeu, e nao na autoridade:

- **IP**: o da requisicao (`ip_do_cliente`) tem de estar numa das faixas da conta, quando ha' faixas;
- **requisicao assinada** (RFC 9421), quando a conta ou o tenant a exige: assinatura Ed25519 ou ECDSA
  P-256 sobre `@method`, `@path` e `content-digest` (com corpo), com `created` recente e `nonce` de uso
  unico guardado no Redis durante a janela.

Sem Redis, a requisicao assinada RECUSA (503): nunca se rebaixa a protecao. O limite de chamadas fica na borda
(WAF ou gateway), fora daqui.

Os adapters (`nsj-flask-auth`, `nsj-quart-auth`) entregam a conta como um usuario: `type = "access_token"`,
o identificador reservado no lugar do e-mail e a marca `service_account` (D7).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Mapping

from ._service_account_errors import AuthError, ForbiddenError, UnauthorizedError

PREFIXO_DA_CHAVE = "nsa_"
DOMINIO_RESERVADO = "svc.nasajon.app"
TTL_DO_CACHE_SEGUNDOS = 30.0
JANELA_DA_ASSINATURA_SEGUNDOS = 300
TIMEOUT_SEGUNDOS = 5.0


class ServiceAccountRejected(UnauthorizedError):
    """A chave nao vale (inexistente, vencida, revogada, segredo errado). 401."""


class ServiceAccountForbidden(ForbiddenError):
    """A chave vale, e a requisicao fere uma protecao da conta (IP ou assinatura). 403."""

    def __init__(self, mensagem: str = "", *, detalhe: str | None = None, motivo: str = "protecao") -> None:
        super().__init__(mensagem, detalhe=detalhe)
        self.motivo = motivo


class ServiceAccountUnavailable(AuthError):
    """A autoridade da chave ou o Redis das protecoes nao responde. 503, nunca 401."""

    status_code = 503


def is_service_account_key(valor: Any) -> bool:
    return isinstance(valor, str) and valor.startswith(PREFIXO_DA_CHAVE)


def is_reserved_identifier(email: Any) -> bool:
    """E-mail no dominio reservado: so' a service account o tem (constraint do Diretorio)."""
    return isinstance(email, str) and email.strip().lower().endswith("@" + DOMINIO_RESERVADO)


#: `(url, corpo, cabecalhos, timeout) -> (status, corpo)`. Trocavel nos testes.
Transporte = Callable[[str, bytes, dict[str, str], float], tuple[int, bytes]]


def _transporte_urllib(url: str, corpo: bytes, cabecalhos: dict[str, str], timeout: float) -> tuple[int, bytes]:
    pedido = urllib.request.Request(url, data=corpo, headers=cabecalhos, method="POST")
    try:
        with urllib.request.urlopen(pedido, timeout=timeout) as resposta:  # noqa: S310 (URL da configuracao)
            return resposta.status, resposta.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read() or b""


class ServiceAccountAuthenticator:
    """Pergunta a' autoridade de quem e' a chave, com cache curto por processo.

    `autenticar_em` substitui a chamada HTTP: e' o que a propria erp4-authorization-api usa, para nao
    chamar a si mesma.
    """

    def __init__(
        self,
        url_provider: Callable[[], str | None],
        *,
        autenticar_em: Callable[[str], dict] | None = None,
        transporte: Transporte | None = None,
        relogio: Callable[[], float] = time.monotonic,
        ttl: float = TTL_DO_CACHE_SEGUNDOS,
    ) -> None:
        self._url_provider = url_provider
        self._autenticar_em = autenticar_em
        self._transporte = transporte or _transporte_urllib
        self._relogio = relogio
        self._ttl = ttl
        self._cache: dict[str, tuple[float, dict]] = {}
        self._trava = threading.Lock()

    def autenticar(self, chave: str) -> dict:
        digest = hashlib.sha256(chave.encode()).hexdigest()
        agora = self._relogio()
        with self._trava:
            guardado = self._cache.get(digest)
        if guardado is not None and agora - guardado[0] < self._ttl:
            return guardado[1]
        conta = self._autenticar_em(chave) if self._autenticar_em else self._autenticar_http(chave)
        with self._trava:
            self._cache[digest] = (agora, conta)
            if len(self._cache) > 10_000:
                self._cache.clear()
        return conta

    def _autenticar_http(self, chave: str) -> dict:
        base = (self._url_provider() or "").strip()
        if not base:
            raise ServiceAccountUnavailable(
                "Autoridade da service account nao configurada.", detalhe="AUTHORIZATION_API_URL ausente"
            )
        url = f"{base.rstrip('/')}/service-accounts/authenticate"
        corpo = json.dumps({"key": chave}).encode()
        try:
            status, bruto = self._transporte(
                url, corpo, {"Content-Type": "application/json", "Accept": "application/json"}, TIMEOUT_SEGUNDOS
            )
        except (urllib.error.URLError, OSError) as exc:
            raise ServiceAccountUnavailable(
                "Autoridade da service account inacessivel.", detalhe=f"{url}: {exc}"
            ) from exc
        if status in (401, 403):
            raise ServiceAccountRejected("Chave de service account invalida.", detalhe=f"autoridade HTTP {status}")
        if status != 200:
            raise ServiceAccountUnavailable(
                "Autoridade da service account indisponivel.", detalhe=f"{url}: HTTP {status}"
            )
        try:
            conta = json.loads(bruto.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ServiceAccountUnavailable("Resposta ilegivel da autoridade da service account.") from exc
        if not isinstance(conta, dict) or not conta.get("conta_id") or not is_reserved_identifier(conta.get("email")):
            raise ServiceAccountUnavailable("Resposta da autoridade da service account fora do contrato.")
        return conta


def user_data_da_conta(conta: Mapping[str, Any]) -> dict:
    """O `g.user_data` da conta: um usuario (`access_token`) com a marca `service_account` (D7)."""
    return {
        "name": conta.get("nome"),
        "email": conta["email"],
        "type": "access_token",
        "user_id": conta.get("conta_id"),
        "apikey_tipo": None,
        "apikey_tenant": None,
        "azp": None,
        "service_account": {
            "conta_id": conta.get("conta_id"),
            "alcance": conta.get("alcance"),
            "tenant": conta.get("tenant"),
            "tenants": conta.get("tenants"),
            "prefixo": conta.get("prefixo"),
            "version": conta.get("version"),
        },
    }


# --------------------------------------------------------------------- protecoes (D5)


def ip_do_cliente(cabecalhos: Mapping[str, str], par_tcp: str | None, *, cabecalho: str | None = None,
                  proxies_confiaveis: str | None = None) -> str | None:
    """O IP do cliente para a faixa da conta.

    O cabecalho (`SERVICE_ACCOUNT_IP_HEADER`, padrao `X-Real-IP`) so' vale quando a conexao vem de um proxy
    confiavel (`SERVICE_ACCOUNT_TRUSTED_PROXIES`, faixas separadas por virgula). Fora disso, qualquer um que
    alcance o servico escreveria o proprio IP, e vale o par TCP. Sem proxy confiavel configurado, o cabecalho
    nunca vale. Com varios IPs no cabecalho, vale o ultimo, o que o proxy confiavel acrescentou."""
    nome = (cabecalho if cabecalho is not None else os.getenv("SERVICE_ACCOUNT_IP_HEADER") or "X-Real-IP").strip()
    faixas = proxies_confiaveis if proxies_confiaveis is not None else os.getenv("SERVICE_ACCOUNT_TRUSTED_PROXIES")
    par = (par_tcp or "").strip() or None
    if par is None or not _em_alguma_faixa(par, faixas or ""):
        return par
    valor = next((v for k, v in cabecalhos.items() if k.lower() == nome.lower()), None)
    ultimo = (valor or "").split(",")[-1].strip()
    return ultimo or par


def _em_alguma_faixa(ip: str, faixas: str) -> bool:
    try:
        endereco = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for faixa in faixas.split(","):
        try:
            if faixa.strip() and endereco in ipaddress.ip_network(faixa.strip(), strict=False):
                return True
        except ValueError:
            continue
    return False



def conferir_protecoes(
    conta: Mapping[str, Any],
    *,
    ip: str | None,
    metodo: str,
    caminho: str,
    cabecalhos: Mapping[str, str],
    corpo: bytes | None,
    redis: Any,
    agora: float | None = None,
) -> None:
    """Aplica as protecoes da conta a' requisicao. Levanta a recusa; volta sem nada se passa."""
    protecoes = conta.get("protecoes") or {}
    agora = time.time() if agora is None else agora
    try:
        _conferir_ip(protecoes.get("allowed_cidrs") or [], ip)
        if protecoes.get("require_signature"):
            _conferir_assinatura(conta, protecoes, metodo=metodo, caminho=caminho, cabecalhos=cabecalhos,
                                 corpo=corpo or b"", redis=redis, agora=agora)
    except ServiceAccountForbidden as recusa:
        raise  # The Flask response hook records this request exactly once.


def conferir_tenant(conta: Mapping[str, Any], tenant: Any) -> None:
    """O tenant pedido tem de ser um em que a conta age: o dela (de tenant) ou um com cadeira global disponivel
    (de sistema, `tenants` da autoridade). Sem tenant na requisicao, nada a conferir aqui. 403."""
    if tenant is None or str(tenant).strip() == "":
        return
    permitidos = {str(t) for t in (conta.get("tenants") or ([conta["tenant"]] if conta.get("tenant") else []))}
    if str(tenant).strip() not in permitidos:
        raise ServiceAccountForbidden("Esta service account nao age nesta Instalacao.",
                                      detalhe=f"tenant {tenant} fora de {sorted(permitidos)}", motivo="tenant")


def _conferir_ip(faixas: list[str], ip: str | None) -> None:
    if not faixas:
        return
    try:
        endereco = ipaddress.ip_address((ip or "").strip())
    except ValueError as exc:
        raise ServiceAccountForbidden("IP de origem nao permitido para esta service account.",
                                      detalhe=f"ip ilegivel: {ip!r}", motivo="ip") from exc
    for faixa in faixas:
        try:
            if endereco in ipaddress.ip_network(faixa, strict=False):
                return
        except ValueError:
            continue
    raise ServiceAccountForbidden("IP de origem nao permitido para esta service account.", detalhe=f"ip={endereco}",
                                  motivo="ip")


_RE_ENTRADA = re.compile(r'^\s*([a-z0-9_*-]+)=\(([^)]*)\)\s*(.*)$', re.I)
_RE_COMPONENTE = re.compile(r'"([^"]+)"')
_RE_PARAMETRO = re.compile(r';\s*([a-z0-9_-]+)=("([^"]*)"|-?\d+)', re.I)
_RE_ASSINATURA = re.compile(r'^\s*([a-z0-9_*-]+)=:([A-Za-z0-9+/=]+):\s*$', re.I)


def _conferir_assinatura(conta, protecoes, *, metodo, caminho, cabecalhos, corpo, redis, agora) -> None:
    def recusa(detalhe: str):
        raise ServiceAccountForbidden("Requisicao assinada invalida para esta service account.", detalhe=detalhe,
                                      motivo="assinatura")

    cab = {k.lower(): v for k, v in cabecalhos.items()}
    entrada = (cab.get("signature-input") or "").split(",")[0]
    assinatura = (cab.get("signature") or "").split(",")[0]
    m_entrada, m_assinatura = _RE_ENTRADA.match(entrada), _RE_ASSINATURA.match(assinatura)
    if not m_entrada or not m_assinatura or m_entrada.group(1) != m_assinatura.group(1):
        recusa("Signature-Input/Signature ausentes ou sem o mesmo rotulo")

    componentes = _RE_COMPONENTE.findall(m_entrada.group(2))
    texto_dos_parametros = m_entrada.group(3)
    parametros = {m.group(1).lower(): (m.group(3) if m.group(3) is not None else int(m.group(2)))
                  for m in _RE_PARAMETRO.finditer(texto_dos_parametros)}

    caminho_sem_query, _, query = caminho.partition("?")
    # Com query string, a assinatura a cobre (`@query`, RFC 9421 §2.2.7): sem isto, quem estivesse no caminho trocaria
    # `?id=` ou `?tenant=` sem invalidar a assinatura.
    exigidos = {"@method", "@path"} | ({"content-digest"} if corpo else set()) | ({"@query"} if query else set())
    if any(k.lower() == "x-tenant" for k in cabecalhos.keys()):
        exigidos.add("x-tenant")
    if not exigidos <= set(componentes):
        recusa(f"componentes cobertos insuficientes: {componentes}")
    created = parametros.get("created")
    if not isinstance(created, int) or abs(agora - created) > JANELA_DA_ASSINATURA_SEGUNDOS:
        recusa("created ausente ou fora da janela")
    nonce = parametros.get("nonce")
    if not isinstance(nonce, str) or not 8 <= len(nonce) <= 128:
        recusa("nonce ausente")
    chave = next((c for c in protecoes.get("chaves_publicas") or [] if c.get("key_id") == parametros.get("keyid")), None)
    if chave is None:
        recusa("keyid desconhecido")

    if corpo:
        _conferir_content_digest(cab.get("content-digest") or "", corpo, recusa)

    linhas = []
    for componente in componentes:
        if componente == "@method":
            valor = metodo.upper()
        elif componente == "@path":
            valor = caminho_sem_query or "/"
        elif componente == "@query":
            valor = "?" + query
        elif componente.startswith("@"):
            recusa(f"componente derivado nao suportado: {componente}")
        else:
            if componente not in cab:
                recusa(f"header coberto ausente: {componente}")
            valor = " ".join(cab[componente].split())
        linhas.append(f'"{componente}": {valor}')
    linhas.append(f'"@signature-params": ({m_entrada.group(2)}){texto_dos_parametros}')
    base = "\n".join(linhas).encode()

    try:
        assinatura_bytes = base64.b64decode(m_assinatura.group(2), validate=True)
    except (binascii.Error, ValueError):
        recusa("assinatura em base64 invalido")
    if not _verificar(chave, base, assinatura_bytes):
        recusa("assinatura nao confere")

    # Nonce de uso unico durante a janela, depois de a assinatura conferir (nao queima nonce alheio).
    if redis is None:
        raise ServiceAccountUnavailable("Nonce da requisicao assinada sem Redis.", detalhe="redis ausente")
    try:
        novo = redis.set(f"service-account:nonce:{conta['conta_id']}:{nonce}", "1",
                         nx=True, ex=2 * JANELA_DA_ASSINATURA_SEGUNDOS)
    except Exception as exc:
        raise ServiceAccountUnavailable("Redis do nonce indisponivel.", detalhe=str(exc)) from exc
    if not novo:
        recusa("nonce ja' usado")


def _conferir_content_digest(valor: str, corpo: bytes, recusa) -> None:
    for parte in valor.split(","):
        nome, _, resto = parte.strip().partition("=")
        algoritmo = {"sha-256": hashlib.sha256, "sha-512": hashlib.sha512}.get(nome.strip().lower())
        if algoritmo and resto.startswith(":") and resto.endswith(":"):
            esperado = base64.b64encode(algoritmo(corpo).digest()).decode()
            if resto.strip(":") == esperado:
                return
            recusa("content-digest nao confere com o corpo")
    recusa("content-digest ausente")


def _verificar(chave: Mapping[str, Any], base: bytes, assinatura: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    try:
        publica = load_pem_public_key(str(chave.get("public_key_pem") or "").encode())
        if chave.get("algorithm") == "ed25519" and isinstance(publica, ed25519.Ed25519PublicKey):
            publica.verify(assinatura, base)
            return True
        if chave.get("algorithm") == "ecdsa-p256-sha256" and isinstance(publica, ec.EllipticCurvePublicKey):
            if len(assinatura) != 64:  # RFC 9421 §3.3.4: r || s, 32 bytes cada
                return False
            der = encode_dss_signature(int.from_bytes(assinatura[:32], "big"), int.from_bytes(assinatura[32:], "big"))
            publica.verify(der, base, ec.ECDSA(hashes.SHA256()))
            return True
    except (InvalidSignature, ValueError, TypeError):
        return False
    return False
