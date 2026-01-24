# Autenticação OAuth2 no ems-bus - Guia de Referência

## 1. Visão Geral

O **ems-bus** implementa um servidor OAuth 2.0 (RFC 6749) completo, projetado para oferecer segurança e interoperabilidade com clientes modernos e frameworks como Authlib, Spring Security, entre outros.

Além dos fluxos de autorização padrão, o servidor suporta **Discovery** (RFC 8414), permitindo configuração automática por parte dos clientes.

### 1.1. Principais Funcionalidades

*   **OAuth 2.0 Authorization Framework (RFC 6749)**
    *   Suporte aos principais Grant Types:
        *   Authorization Code Grant `authorization_code`
        *   Resource Owner Password Credentials Grant `password`
        *   Client Credentials Grant `client_credentials`
        *   Refresh Token `refresh_token`
    *   Implementação de segurança para redirecionamento e validação de scopes.

*   **OAuth 2.0 Access Token Usage (RFC 6750)**
    *   Suporte a tokens do tipo `Bearer`.

*   **OAuth 2.0 Authorization Server Metadata (RFC 8414)**
    *   Endpoint de descoberta `.well-known/oauth-authorization-server` para configuração automática de clientes.

## 2. Metadados e Discovery (RFC 8414)

O servidor expõe suas capacidades através de um documento JSON padronizado. Isso permite que bibliotecas de cliente se configurem sozinhas, sem necessidade de hardcoded URLs.

**Endpoint:**
`GET /.well-known/oauth-authorization-server`

**Exemplo de Resposta:**
```json
{
  "issuer": "https://seu-servidor.com",
  "authorization_endpoint": "https://seu-servidor.com/authorize",
  "token_endpoint": "https://seu-servidor.com/authorize",
  "grant_types_supported": [
    "authorization_code",
    "client_credentials",
    "password",
    "refresh_token"
  ],
  "response_types_supported": [
    "code",
    "token"
  ],
  "scopes_supported": [
    "user_db",
    "user_fs",
    "admin"
  ],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic"
  ]
}
```

> **Nota sobre Scopes:** A lista `scopes_supported` é gerada dinamicamente a partir da configuração `auth_default_scope` no `emsbus.conf`. Isso garante que o metadata reflita exatamente o que o servidor suporta.

## 3. Fluxos de Autenticação Suportados

### 3.1. Authorization Code Grant (`authorization_code`)

É o fluxo mais seguro e recomendado para aplicações Web (Server-side) e SPAs (com PKCE - *em breve*).

1.  **O Cliente redireciona o usuário** para `/authorize?response_type=code&client_id=...&redirect_uri=...&scope=...`
2.  **O Usuário faz login** na página segura do barramento.
3.  **O Servidor redireciona de volta** para `redirect_uri` com um `code`.
4.  **O Cliente troca o código** por um token chamando `/authorize` via POST (back-channel).

**Parâmetros Extras do ems-bus:**
*   Em um ambiente com múltiplos frontends, o `ems-bus` retorna `200 OK` com `{"redirect": "..."}` para solicitações AJAX na página de login, permitindo redirecionamento controlado pelo JavaScript.

### 3.2. Resource Owner Password Credentials Grant (`password`)

Usado quando o cliente é altamente confiável (ex: app oficial da mesma empresa). O usuário entrega login/senha direto para o aplicativo.

**Requisição:**
`POST /authorize`
```
grant_type=password
username=seu_usuario
password=sua_senha
scope=user_db
```

### 3.3. Client Credentials Grant (`client_credentials`)

Para comunicação máquina-a-máquina (M2M), onde não há usuário final. O cliente se autentica para acessar seus próprios recursos.

**Requisição:**
`POST /authorize` (Autenticação via Basic Auth ou parâmetros no corpo)
```
grant_type=client_credentials
scope=admin
```

### 3.4. Refresh Token (`refresh_token`)

Quando o `access_token` expira (padrão: 1h), o cliente usa o `refresh_token` (padrão: 30 dias) para obter um novo par de tokens sem incomodar o usuário.

## 4. Configuração (`emsbus.conf`)

O comportamento do servidor OAuth2 pode ser ajustado no arquivo de configuração principal.

| Parâmetro | Descrição | Padrão |
| :--- | :--- | :--- |
| `authorization` | Define o modo de autenticação global. Use `"oauth2"`. | `"oauth2"` |
| `auth_default_scope` | Lista de escopos que o servidor suporta e anuncia no metadata. | `["user_db", "user_fs"]` |
| `oauth2_refresh_token` | Tempo de vida do Refresh Token (em segundos). | `7200` (2h) |
| `oauth2_resource_owner_fields` | Campos do usuário que serão retornados no JSON do token. | `["id", "login", "email"]` |
| `rest_auth_url` | URL pública do endpoint de autorização (importante para o metadata). | *Auto-detectado* |

### Exemplo de Configuração
```json
{
  "authorization": "oauth2",
  "auth_default_scope": [
    "user_db",
    "user_fs",
    "admin",
    "api_write"
  ],
  "oauth2_refresh_token": 2592000,
  "rest_base_auth_url": "https://api.empresa.com"
}
```

## 5. Compatibilidade e Interoperabilidade

O `ems-bus` foi testado e validado com os seguintes clientes/bibliotecas:

*   **Authlib (Python):** Funciona nativamente usando o modo de autodescoberta (`server_metadata_url`).
    *   *Dica:* O `ems-bus` suporta `client_secret_basic` para autenticação do cliente no endpoint de token.
*   **Postman:** Suporta todos os fluxos na aba "Authorization" > "OAuth 2.0".
*   **curl:** Ferramenta padrão para testes manuais.

### Tratamento de Scopes
*   Na resposta do Token (RFC 6749 Seção 5.1), o parâmetro `scope` é retornado para confirmar quais permissões foram concedidas.
*   Se o cliente solicitar um escopo não mapeado no `auth_default_scope`, a solicitação pode ser ajustada ou rejeitada dependendo da política de segurança configurada.

### Tratamento de Redirect URI
*   O servidor valida estritamente a `redirect_uri` enviada contra a cadastrada no cliente.
*   Para clientes legados, se a `redirect_uri` não for enviada no `token request`, o servidor usa a que foi gravada durante o `code request`.

---
**Autor:** Equipe ErlangMS / Antigravity
**Versão:** 2.0
