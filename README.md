# nsj-flask-auth

## Introdução

Este módulo tem como objetivo fornecer um fluxo básico de autenticação e autorização para APIs Flask no contexto da Nasajon.

## Utilização básica

Suponhamos uma aplicação mínima de Flask:

```python
from flask import Flask

app = Flask(__name__)

@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"
```

Neste exemplo queremos proteger o endpoint "hello_world" com autenticação e autorização.

Criemos na raiz da nossa aplicação (a mesma pasta onde se encontra o código da nossa API citada acima) o arquivo `auth.py`:

```python
from nsj_flask_auth import Auth, Scope

auth = Auth(DIRETORIO_ENDPOINT, PROFILE_ENDPOINT, API_KEY, scope=Scope.GRUPO_EMPRESARIAL, user_scope_permissions=["permissao_1", "permissao_2"])
```

E criamos uma instância da classe Auth disponiblizada no módulo com os parametros:

* DIRETORIO_ENDPOINT: URI Base do diretório que será usado para validar as api-keys recebidas e consultar as permissões dos usuários.
* PROFILE_ENDPOINT: URI do serviço de autenticação da Nasajon para validação de access_tokens.
* API_KEY: Chave de autenticação da sua aplicação.

E agora podemos usar o módulo na nossa aplicação:

```python
from flask import Flask
from auth import auth

app = Flask(__name__)

@app.route("/")
@auth.requires_api_key_or_access_token()
def hello_world():
    return "<p>Hello, World!</p>"
```

Esta é a implementação mínima do módulo. Mais detalhes sobre parametrizações e métodos disponíveis serão abordados ao longo desta documentação.

## Parametros disponíveis para inicialização

* DIRETORIO_BASE_URI: URI Base do diretório que será usado para validar as api-keys recebidas e consultar as permissões dos usuários.
* PROFILE_URI: URI do serviço de autenticação da Nasajon para validação de access_tokens.
* DIRETORIO_API_KEY: Chave de autenticação da sua aplicação.
* API_KEY_HEADER: Nome do cabeçalho que será usado para receber a chave de autenticação.
* ACCESS_TOKEN_HEADER: Nome do cabeçalho que será usado para receber o access_token.
* USER_INTERNAL_PERMISSIONS: lista de permissões internas que o usuário precisa para acessar os endpoints da aplicação.
* USER_SCOPE_PERMISSIONS: lista de permissões em dado escopo que o usuário precisa ter para acessar os endpoints da aplicação.
* SCOPE: escopo em que as permissões (vide parâmetro acima) devem ser verificadas. Pode ser tenant, grupo empresarial, empresa e estabelecimento. O padrão é grupo empresarial.
* APP_REQUIRED_PERMISSIONS: lista de permissões que o sistema precisa para acessar os endpoints da aplicação.
* CACHING_SERVICE: instancia do serviço de cache. Até o momento este recurso só foi validado com instancias do módulo flask_caching.

Caso alguma permissão seja informada no momento de inicialização da classe é importante notar que ela será aplicada a todos os endpoints que forem decorados pelos métodos disponíves na classe Auth.

## Métodos disponíveis

### requires_api_key

Decorator que garante o envio de uma api-key na requisição. O decorator recebe um parâmetro opcional que é a lista de permissões exigidas para o sistema solicitante acessar o endpoint. Estas permissões serão aplicadas somente ao endpoint decorado.

### requires_access_token

Decorator que garante o envio de um access_token na requisição. O decorator recebe um parâmetro opcional que é a lista de permissões internas (`user_ionternal_permissions`) exigidas para o usuários solicitante acessar o endpoint. Este decorator também aceita permissões por escopo, permitindo passar as permissões necessárias dentro de um dado escopo (tenant, grupo empresarial, empresa ou estabelecimento), além do dado escopo. As permissões serão aplicadas somente ao endpoint decorado.

### requires_api_key_or_access_token

Decorator que implementa os dois fluxos de autenticação disponíveis (api-key e access_token). Importante notar que neste fluxo o primeiro parâmetro verificado é api-key e caso este seja autorizado o acesso é garantido, independente do access_token enviado.

## Acessar dados do usuário

Os dados do usuário estão disponíveis no contexto da aplicação Flask.

```python
from flask import g

user_profile = g.profile

```