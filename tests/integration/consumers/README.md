# Cinco consumidores — integração local

Escopo: Atendimento, estoque-api, tesouraria-api, ErpApiWeb e estoque-backend (Roteirização). Não acessa SSO nem contas reais. Segredos e chaves sintéticos são gerados em .local, que é ignorado pelo Git.

prepare.py extrai o serviço/DAO de autenticação da revisão imutável 9953aef7cc7a342c81c4d3e656780fd50f9a048e de nav. O adaptador SQL de transporte é local; perfil/provisões, OAuth Client Credentials e Multidb são fixtures explícitas. As aplicações executam router, middleware, controller e SQL reais sobre schemas mínimos gerados a partir das declarações do repositório. Não representa schema ERP completo nem validação dos endpoints reais de DEV.

Prerequisitos: Docker, clones locais em SERVICE_ACCOUNT_WORKSPACE (padrão /home/rodrigo/work), dependências instaladas, código MDA gerado, imagens PHP usadas pelo prepare e service-account-fixture:dev. O prepare nunca lê .env do desenvolvedor. Parâmetros e todas as credenciais são sintéticos.

Execução:
1. python3 prepare.py
2. docker compose -f .local/compose.json up -d --wait
3. docker compose -f .local/compose.json exec -T client python /fixture/seed.py
4. docker compose -f .local/compose.json exec -T client python /fixture/smoke.py
5. python3 run-infrastructure.py
6. python3 audit.py
7. docker compose -f .local/compose.json down -v

O seed requer banco novo. Usar SERVICE_ACCOUNT_POSTGRES_IMAGE=postgres:11.5 e SERVICE_ACCOUNT_POSTGRES_VERSION=11.5 para a segunda versão. Somente o projeto service-account-consumers é gerenciado. Portas 18900–18905 ficam vinculadas a 127.0.0.1.

A bateria verifica as 12 operações GET declaradas, provisões/entidades, tenant e IDs alheios, rotas humanas, métodos/corpo, transportes, URI codificada, expiração/revogação, IP forjado, Ed25519/P256, replay entre consumidores, Redis persistente e quedas da autoridade/Redis. audit.py verifica logs em cinco passagens de decodificação, transporte sem chave fora da autoridade e conexão de banco própria.

As respostas/evidências salvas contêm apenas nomes de cenários e status; config.json e arquivos PEM nunca são artefatos de CI. Remover .local/config.json e PEM após finalizar. Para testar imagens Python empacotadas, prepare.py aceita SERVICE_ACCOUNT_PACKAGED_IMAGES=1.

