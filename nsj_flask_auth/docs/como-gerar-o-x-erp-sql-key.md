# Geração do Token X-ERP-SQL-KEY

Esta documentação descreve a lógica para a construção do token de autenticação exigido no header `X-ERP-SQL-KEY`.

---

### 1. Composição do Header
O valor do header deve ser uma string codificada em **Base64** seguindo o formato:
`CNPJ:HASH_SHA256`

---

### 2. Gerando o Payload do Hash
O `HASH_SHA256` deve ser gerado a partir de uma **String Base** composta pela concatenação literal (sem separadores) dos seguintes elementos, nesta ordem:

| Ordem | Elemento | Regras de Formatação |
| :--- | :--- | :--- |
| **1º** | **URL** | URL completa da requisição, em minúsculo, removendo espaços e a barra final (`/`). |
| **2º** | **SERIAL** | Chave secreta (AppKey) vinculada ao CNPJ, sem espaços laterais. |
| **3º** | **TIMESTAMP** | Timestamp Unix do início da hora atual (Hora Cheia). Cálculo: `(Timestamp_Atual / 3600) * 3600`. |
| **4º** | **BODY** | Conteúdo bruto do corpo da requisição (Raw Body) após normalização. |

---

### 3. Normalização do Body (Obrigatório)
Para garantir a integridade do Hash entre diferentes sistemas, o corpo da requisição (JSON, texto, etc.) deve passar pelo seguinte processo antes de ser anexado à String Base:

1. **Remoção de Whitespaces:** Devem ser removidos **todos** os caracteres de espaço, tabulações (`\t`) e quebras de linha (`\n` ou `\r`).
2. **Truncamento:** Após a remoção dos espaços, utilize apenas os **primeiros 500 caracteres** da string resultante.
3. **Casos Especiais:** Se a requisição não possuir corpo (como em métodos GET), este campo deve ser tratado como uma string vazia.



---

### 4. Passo a Passo
1. Calcule o **Timestamp** da hora cheia.
2. Formate a **URL** removendo a última barra.
3. Normalize o **Body** eliminando todos os espaços e quebras de linha, limitando a 500 caracteres.
4. Concatene tudo: `URL + SERIAL + TIMESTAMP + BODY`.
5. Gere o hash **SHA-256** (em formato hexadecimal minúsculo) desta concatenação.
6. Monte a string `CNPJ:HASH`.
7. Codifique o resultado final em **Base64**.

---

### 5. Exemplo Visual da String Base
Se os dados forem:
* **URL:** `http://localhost/api/`
* **Serial:** `ABC-123`
* **TS:** `1773165600`
* **Body:** `{"id": 10}`

A string antes do hash deve ser exatamente:
`http://localhost/apiABC-1231773165600{"id":10}`