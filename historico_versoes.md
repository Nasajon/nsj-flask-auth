# Histórico de Versões

## 0.7.0

Novas features:

* Possibilidade de utilizar a nova API de profile (mais rápida).
  * Essa nova API de profile trabalha exclusivamente em cache (Redis), e conta com um worker de atualização dos profiles (por push notification). Assim, a nova API é muito superior em performance a antiga (chegando a cerca de 10 vezes mais rápida, nos testes).

## 0.8.0

Novas features:
* Suporte para apikeys de tenant

## 0.12.0

Novas features:
* Validação do access token por introspection e checagem do client que emitiu o token (`allowed_client_ids`). Opcional e retrocompatível.

Correções:
* POST/PUT/PATCH com corpo não JSON (multipart, form) não dá mais erro 500 nos decorators que conferem o tenant.
* A conferência do tenant da requisição aceita o código do tenant, além do id.
