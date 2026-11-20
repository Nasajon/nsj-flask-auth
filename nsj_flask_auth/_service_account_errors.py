"""Contrato canonico de erro de autenticacao e autorizacao (ADR-0095 secao 8.6).

A ADR exige que Flask, Quart e os adapters TypeScript entreguem "os mesmos
resultados para `401`, `403`, tenant ausente, token expirado e audiencia
invalida". Contrato aqui e' isso: uma hierarquia unica, com o status HTTP
decidido pela classe e nao por cada `except` de cada servico.

A separacao 401 x 403 nao e' estetica. A secao 18 exige teste separado para
"JWT adulterado retorna 401" e "persona autenticada sem permissao retorna 403".
Colapsar os dois num erro generico torna esses dois testes indistinguiveis, e
foi assim que autorizacao passou a parecer autenticacao em varios servicos.

Hierarquia e status:

    AuthError                  -> 503  algo no fluxo de auth quebrou
    +- UnauthorizedError       -> 401  credencial ausente, mal-formada ou rejeitada
    |  +- InvalidTokenError    -> 401  assinatura, exp, nbf, iss, aud ou typ invalidos
    |  +- MissingTokenError    -> 401  nenhuma credencial apresentada
    +- ForbiddenError          -> 403  autenticado, sem permissao para a operacao
    |  +- MissingTenantError   -> 403  operacao exige tenant e o contexto nao tem
    +- ProfileUnavailableError -> 503  a fonte de perfil nao respondeu
"""

from __future__ import annotations


class AuthError(Exception):
    """Raiz da hierarquia. Use sempre a subclasse especifica.

    `status_code` e' atributo de CLASSE de proposito: o handler HTTP le
    `type(exc).status_code` sem precisar de um mapa paralelo que envelhece
    quando alguem acrescenta uma subclasse.
    """

    status_code: int = 503

    def __init__(self, mensagem: str = "", *, detalhe: str | None = None) -> None:
        super().__init__(mensagem)
        # `detalhe` carrega o motivo tecnico (ex.: "aud esperado erpilot-agent,
        # recebido focusbi"). Fica FORA da resposta HTTP por padrao: dizer ao
        # cliente exatamente qual claim falhou entrega um oraculo para quem
        # esta tentando forjar token. Vai para o log.
        self.detalhe = detalhe


class UnauthorizedError(AuthError):
    """Credencial ausente, mal-formada ou rejeitada."""

    status_code = 401


class MissingTokenError(UnauthorizedError):
    """Nenhuma credencial apresentada."""


class InvalidTokenError(UnauthorizedError):
    """Token rejeitado: assinatura, `exp`, `nbf`, `iss`, `aud` ou tipo."""


class ForbiddenError(AuthError):
    """Autenticado, porem sem permissao para a operacao."""

    status_code = 403


class MissingTenantError(ForbiddenError):
    """A operacao exige tenant e o contexto nao tem um selecionado."""


class ProfileUnavailableError(AuthError):
    """A fonte de perfil (Diretorio ou Local Auth) nao respondeu."""

    status_code = 503
