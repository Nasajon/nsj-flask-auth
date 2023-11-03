from flask import Flask
from nsj_flask_auth import Auth, Scope


app = Flask("app")

auth = Auth(
    diretorio_base_uri="https://dir.dev.nasajonsistemas.com.br",
    profile_uri="https://auth.dev.nasajonsistemas.com.br/auth/realms/DEV/protocol/openid-connect/userinfo",
    diretorio_api_key="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzaXN0ZW1hIjozMTAsInRpcG8iOiJzaXN0ZW1hIn0.OrfjG4yc43a2RuggfBENUWMTfw9wcdszKlPWWMGUJuQ"
)

@app.route("/ping/", methods=["GET"])
def ping():
    return ({"ping": "pong"}, 200, {})

@app.route("/escopo-tenant/", methods=["GET", "POST"])
@auth.requires_access_token(scope=Scope.TENANT, user_scope_permissions=["acesso_total"])
def teste__permissao_escopo_tenant():
    return ({}, 200, {})

@app.route("/escopo-grupo-empresarial/", methods=["GET", "POST"])
@auth.requires_access_token(scope=Scope.GRUPO_EMPRESARIAL, user_scope_permissions=["acesso_total"])
def teste__permissao_escopo_grupo_empresarial():
    return ({}, 200, {})

@app.route("/escopo-grupo-empresarial/instalacao/", methods=["GET", "POST"])
@auth.requires_instalacao_key(scope=Scope.GRUPO_EMPRESARIAL, user_scope_permissions=["acesso_total"])
def teste__permissao_escopo_grupo_empresarial():
    return ({}, 200, {})

@app.route("/escopo-empresa/", methods=["GET", "POST"])
@auth.requires_access_token(scope=Scope.EMPRESA, user_scope_permissions=["acesso_total"])
def teste__permissao_escopo_empresa():
    return ({}, 200, {})

@app.route("/escopo-estabelecimento/", methods=["GET", "POST"])
@auth.requires_access_token(scope=Scope.ESTABELECIMENTO, user_scope_permissions=["acesso_total"])
def teste__permissao_escopo_estabelecimento():
    return ({}, 200, {})


if __name__ == '__main__':
    app.run(port=5000)