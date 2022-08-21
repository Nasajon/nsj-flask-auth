from flask import Flask
from nsj_flask_auth import Scope
from tests.test_nsj_flask_auth import auth

app = Flask("app")

@app.route("/ping/", methods=["GET"])
def ping():
    return ({"ping": "pong"}, 200, {})

@app.route("/escopo-tenant/", methods=["GET", "POST"])
@auth.requires_access_token(scope=Scope.TENANT, user_scope_permissions=[])
def teste__permissao_escopo_tenant():
    return ({}, 200, {})

@app.route("/escopo-grupo-empresarial/", methods=["GET", "POST"])
@auth.requires_access_token(scope=Scope.GRUPO_EMPRESARIAL, user_scope_permissions=[])
def teste__permissao_escopo_grupo_empresarial():
    return ({}, 200, {})

@app.route("/escopo-empresa/", methods=["GET", "POST"])
@auth.requires_access_token(scope=Scope.EMPRESA, user_scope_permissions=[])
def teste__permissao_escopo_empresa():
    return ({}, 200, {})

@app.route("/escopo-estabelecimento/", methods=["GET", "POST"])
@auth.requires_access_token(scope=Scope.ESTABELECIMENTO, user_scope_permissions=[])
def teste__permissao_escopo_estabelecimento():
    return ({}, 200, {})


if __name__ == '__main__':
    app.run(port=5000)