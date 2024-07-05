# pylint: disable=C0301, C0114, C0115, C0116, W0718, W0719, W1203, W3101, C0415, C0411, C0202
from flask import Flask
from nsj_flask_auth import Auth, Scope, ProfileVendor


app = Flask("app")

# Profile pelo Diretório
auth = Auth(
    diretorio_base_uri="https://dir.nasajon.dev",
    profile_uri="https://auth.nasajon.dev/auth/realms/DEV/protocol/openid-connect/userinfo",
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
@auth.requires_instalacao_key(app_required_permissions=["acesso_total"])
def teste__permissao_escopo_instacalacao():
    return ({}, 200, {})

@app.route("/escopo-empresa/", methods=["GET", "POST"])
@auth.requires_access_token(scope=Scope.EMPRESA, user_scope_permissions=["acesso_total"])
def teste__permissao_escopo_empresa():
    return ({}, 200, {})

@app.route("/escopo-estabelecimento/", methods=["GET", "POST"])
@auth.requires_access_token(scope=Scope.ESTABELECIMENTO, user_scope_permissions=["acesso_total"])
def teste__permissao_escopo_estabelecimento():
    return ({}, 200, {})

# Profile pela nova api
auth2 = Auth(
    diretorio_base_uri="https://dir.nasajon.dev",
    profile_uri="https://auth.nasajon.dev/auth/realms/DEV/protocol/openid-connect/userinfo",
    diretorio_api_key="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzaXN0ZW1hIjozMTAsInRpcG8iOiJzaXN0ZW1hIn0.OrfjG4yc43a2RuggfBENUWMTfw9wcdszKlPWWMGUJuQ",
    nsj_auth_api_url="https://api.nasajon.qa",
    nsj_auth_api_token="YWRtaW52MzpjYTQyNjAzNDU5OGQ0ZGIyYTQ2MGE2ODA3MzY1ZjMzMw==",
    profile_vendor=ProfileVendor.NSJ_AUTH_API
)

@app.route("/escopo-tenant-nova-api/", methods=["GET", "POST"])
@auth2.requires_access_token(scope=Scope.TENANT, user_scope_permissions=["efetivar_funcionario"])
def teste__permissao_escopo_tenant_nova_api():
    return ({}, 200, {})

@app.route("/escopo-grupo-empresarial-nova-api/", methods=["GET", "POST"])
@auth2.requires_access_token(scope=Scope.GRUPO_EMPRESARIAL, user_scope_permissions=["efetivar_funcionario"])
def teste__permissao_escopo_grupo_empresarial_nova_api():
    return ({}, 200, {})


@app.route("/escopo-empresa-nova-api/", methods=["GET", "POST"])
@auth2.requires_access_token(scope=Scope.EMPRESA, user_scope_permissions=["efetivar_funcionario"])
def teste__permissao_escopo_empresa_nova_api():
    return ({}, 200, {})

@app.route("/escopo-estabelecimento-nova-api/", methods=["GET", "POST"])
@auth2.requires_access_token(scope=Scope.ESTABELECIMENTO, user_scope_permissions=["efetivar_funcionario"])
def teste__permissao_escopo_estabelecimento_nova_api():
    return ({}, 200, {})


if __name__ == '__main__':
    app.run(port=5000)