# Histórico de Versões

## 0.7.0

Novas features:

* Possibilidade de utilizar a nova API de profile (mais rápida).
  * Essa nova API de profile trabalha exclusivamente em cache (Redis), e conta com um worker de atualização dos profiles (por push notification). Assim, a nova API é muito superior em performance a antiga (chegando a cerca de 10 vezes mais rápida, nos testes).