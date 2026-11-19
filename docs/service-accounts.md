# Adaptador legado de contas de serviço — 0.13.0

Instalar nsj-flask-auth[service-accounts]==0.13.0, Python >=3.10. O adaptador é opt-in: ServiceAccountExtension registra os hooks antes dos hooks da aplicação. ROUTES associa o endpoint Flask e a regra exata; apenas GET sem corpo é autorizado. Policies dos consumidores exigem tenant numérico único, sistema configurado e função positiva sem entidades restritas. Nenhuma rota de funcionário/gestor é liberada.

Autenticação humana permanece no módulo auth. Chaves nsa_ são recusadas antes dos validadores legados, inclusive variações de caixa. A extensão aceita somente X-API-KEY, sem combinação com bearer/header legado/query. Usa autoridade dedicada e vincula o perfil reservado à mesma conta. O marcador autenticado só é atribuído depois de proteções, política e resolução de credenciais próprias do banco.

O núcleo criptográfico framework-neutral em _service_account_core.py e os erros foram extraídos de Nasajon/nav, platform/libs/backend/nsj-auth-core/src/nsj_auth_core, revisão 9953aef7cc7a342c81c4d3e656780fd50f9a048e. Importações foram adaptadas, métricas centralizadas no after_request e cobertura obrigatória de X-Tenant acrescentada. Isso evita impor Python 3.13/Pydantic 2 aos consumidores 3.10/Pydantic 1.9. Alterações futuras no protocolo devem manter testes de interoperabilidade.

AUTHORIZATION_API_URL e Diretório/chave da aplicação precisam apontar para o mesmo ambiente. Cache máximo 30s incluindo consulta; expiração é conferida em todo uso. RFC 9421 Ed25519/P256, IP com proxies explícitos, nonce Redis NX/EX600 compartilhado. Uso é best-effort; anti-replay não é. Falha de proteção/dependência nunca passa para autenticação humana.

Banco: Client Credentials da própria API, audiência nsj-multidb-api, para o endpoint configurado de Multidb com tenant e e-mail reservado. A chave recebida não é encaminhada. O adaptador exige credenciais diretas próprias; role proxy é recusado porque o cliente legado não implementa troca segura. Não há fallback de banco, inclusive ENV=local.

Configuração: SERVICE_ACCOUNT_SYSTEM_ID, SERVICE_ACCOUNT_READ_FUNCTIONS, SERVICE_ACCOUNT_REDIS_URL, SERVICE_ACCOUNT_TRUSTED_PROXIES, SERVICE_ACCOUNT_TOKEN_URL, SERVICE_ACCOUNT_CLIENT_ID, SERVICE_ACCOUNT_CLIENT_SECRET e MULTIDATABASE_API_URL. Segredos vêm do ambiente. A lista vazia de funções bloqueia tudo.

target_filters permite apenas filtros de recurso explicitamente revisados por endpoint (estabelecimento em saldo por endereço e recebimentos). Isso não amplia provisões limitadas por entidade.

Testes offline: python -m pytest -q tests. Testes históricos de SSO externo ficam desativados salvo RUN_LEGACY_LIVE_AUTH_TESTS=1. Não usar essa opção na validação local/CI. CI valida Python 3.10 e 3.13 e constrói a wheel.

Publicar 0.13.0 no índice de distribuição antes de um deploy normal. Enquanto isso, o CI dos consumidores constrói a wheel da revisão imutável registrada em .service-account-library-ref; nenhum segredo nem wheel é versionado.

## Medição pela auditoria (opcional)

As aplicações publicam eventos canônicos em `audit:requests`; a auditoria consolida chamadas, recusas atribuíveis e último uso das chaves. Não há contadores de consumo em `SERVICE_ACCOUNT_REDIS_URL` nem job de resumo no Diretório.

`AUDIT_REDIS_URL` é o canal opcional de publicação, independente do Redis de nonces; `AUDIT_STREAM_KEY` é `audit:requests` e `AUDIT_SERVICE_NAME` identifica esta aplicação. Sem URL não há tentativa de conexão. Em DEV/QA, onde não há API de auditoria, deixar a configuração vazia: autenticação, consultas e gestão continuam funcionando. Se o canal configurado cair, a publicação usa timeout curto e circuito de 30 s, sem alterar a resposta da aplicação. Eventos podem se perder durante a indisponibilidade.

O Diretório consulta o consumo pela API interna da auditoria usando seu próprio OAuth Client Credentials (client permitido, audiência e escopo exclusivos de leitura). Sem essa API/configuração, o consumo informa `disponivel=false`; os painéis exibem “Medição indisponível”, nunca zero chamadas medido. Nenhuma consulta de consumo encaminha a chave `nsa_` ou um token de trabalhador.

`SERVICE_ACCOUNT_REDIS_URL` continua necessário para contas que exigem assinatura: reserva global de nonce com `SET NX EX 600`, compartilhada pelos verificadores, persistência/HA. Se esse Redis falhar, chamadas assinadas retornam 503; desligar auditoria não remove assinatura, IP, permissão ou bloqueio de rotas de funcionário/gestor.
