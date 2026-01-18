# Autenticação OAuth2 no ems-bus - Guia DevOps

## Índice

1. [Visão Geral](#visão-geral)
2. [Conceitos OAuth2](#conceitos-oauth2)
3. [Configuração do Barramento](#configuração-do-barramento)
4. [Fluxos de Autenticação](#fluxos-de-autenticação)
5. [Exemplos com curl](#exemplos-com-curl)
6. [Troubleshooting](#troubleshooting)
7. [Boas Práticas](#boas-práticas)

---

## Visão Geral

O **ems-bus** é um servidor OAuth2 completo que implementa os principais fluxos de autenticação e autorização conforme especificação RFC 6749. Ele permite que aplicações clientes obtenham tokens de acesso para consumir serviços protegidos.

### Características

- ✅ Servidor OAuth2 completo
- ✅ Suporte a múltiplos grant types
- ✅ Tokens JWT com expiração configurável
- ✅ Refresh tokens para renovação
- ✅ Scopes para controle de acesso granular
- ✅ Integração com LDAP e banco de dados

### Endpoints OAuth2

| Endpoint | Método | Descrição |
|----------|--------|-----------|
| `/authorize` | POST | Obter token de acesso |
| `/token` | POST | Renovar token (refresh) |
| `/revoke` | POST | Revogar token |

---

## Conceitos OAuth2

### Grant Types Suportados

#### 1. **Password Grant** (Resource Owner Password Credentials)

Usado quando o cliente possui as credenciais do usuário (username/password).

**Quando usar:**
- Aplicações de confiança (first-party apps)
- CLIs e ferramentas de linha de comando
- Scripts de automação
- Aplicações mobile/desktop próprias

**Fluxo:**
```
Cliente → Envia username/password → Servidor OAuth2 → Retorna access_token
```

#### 2. **Client Credentials Grant**

Usado para autenticação máquina-a-máquina (M2M).

**Quando usar:**
- Serviços backend comunicando entre si
- Jobs agendados (cron jobs)
- Microserviços
- APIs consumindo outras APIs

**Fluxo:**
```
Cliente → Envia client_id/client_secret → Servidor OAuth2 → Retorna access_token
```

#### 3. **Refresh Token Grant**

Usado para renovar um access_token expirado sem solicitar credenciais novamente.

**Quando usar:**
- Quando o access_token expirou
- Para manter sessões longas
- Evitar re-autenticação frequente

**Fluxo:**
```
Cliente → Envia refresh_token → Servidor OAuth2 → Retorna novo access_token
```

### Componentes OAuth2

- **Resource Owner**: Usuário que possui os dados (ex: usuário do sistema)
- **Client**: Aplicação que quer acessar os recursos (ex: app mobile)
- **Authorization Server**: ems-bus (emite tokens)
- **Resource Server**: ems-bus (valida tokens e serve recursos)
- **Access Token**: Token JWT com tempo de vida limitado
- **Refresh Token**: Token de longa duração para renovar access tokens
- **Scope**: Permissões específicas (ex: `user_db`, `user_fs`)

---

## Configuração do Barramento

### Arquivo `emsbus.conf`

```json
{
  "authorization": "oauth2",
  "oauth2_with_check_constraint": false,
  "oauth2_refresh_token": 7200,
  "oauth2_resource_owner_find_permission_with_cpf": true,
  "oauth2_resource_owner_fields": [
    "id", "login", "name", "email", "cpf", 
    "lista_perfil", "lista_permission"
  ],
  "auth_default_scope": ["user_db", "user_fs"]
}
```

### Parâmetros de Configuração

| Parâmetro | Tipo | Padrão | Descrição |
|-----------|------|--------|-----------|
| `authorization` | string | `"oauth2"` | Modo de autenticação (oauth2, basic, public) |
| `oauth2_with_check_constraint` | boolean | `false` | Validação adicional de constraints |
| `oauth2_refresh_token` | integer | `7200` | Tempo de vida do token em segundos (2h) |
| `oauth2_resource_owner_find_permission_with_cpf` | boolean | `true` | Usar CPF para buscar permissões |
| `oauth2_resource_owner_fields` | array | - | Campos retornados no resource_owner |
| `auth_default_scope` | array | `["user_db", "user_fs"]` | Scopes padrão |

### Tempo de Vida dos Tokens

```erlang
% Em include/ems_config.hrl
-define(OAUTH2_DEFAULT_TOKEN_EXPIRY, 3600).   % 1 hora
-define(OAUTH2_MAX_TOKEN_EXPIRY, 2592000).    % 30 dias
```

---

## Fluxos de Autenticação

### 1. Password Grant Flow

```mermaid
sequenceDiagram
    participant User
    participant Client
    participant AuthServer as ems-bus (Auth)
    participant ResourceServer as ems-bus (API)
    
    User->>Client: Fornece username/password
    Client->>AuthServer: POST /authorize<br/>grant_type=password<br/>username=user<br/>password=pass
    AuthServer->>AuthServer: Valida credenciais
    AuthServer-->>Client: access_token + refresh_token
    Client->>ResourceServer: GET /api/resource<br/>Authorization: Bearer {token}
    ResourceServer->>ResourceServer: Valida token
    ResourceServer-->>Client: Dados protegidos
```

### 2. Client Credentials Flow

```mermaid
sequenceDiagram
    participant Client
    participant AuthServer as ems-bus (Auth)
    participant ResourceServer as ems-bus (API)
    
    Client->>AuthServer: POST /authorize<br/>grant_type=client_credentials<br/>client_id=app<br/>client_secret=secret
    AuthServer->>AuthServer: Valida cliente
    AuthServer-->>Client: access_token
    Client->>ResourceServer: GET /api/resource<br/>Authorization: Bearer {token}
    ResourceServer->>ResourceServer: Valida token
    ResourceServer-->>Client: Dados protegidos
```

### 3. Refresh Token Flow

```mermaid
sequenceDiagram
    participant Client
    participant AuthServer as ems-bus (Auth)
    
    Client->>AuthServer: POST /authorize<br/>grant_type=refresh_token<br/>refresh_token={token}
    AuthServer->>AuthServer: Valida refresh_token
    AuthServer-->>Client: novo access_token + refresh_token
```

---

## Exemplos com curl

### 1. Autenticação com Password Grant

#### Requisição

```bash
curl -X POST http://localhost:2301/authorize \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "username=admin" \
  -d "password=senha123" \
  -d "scope=user_db user_fs"
```

#### Resposta de Sucesso

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "8xLOxBtZp8...",
  "scope": "user_db user_fs",
  "resource_owner": {
    "id": 1,
    "login": "admin",
    "name": "Administrador",
    "email": "admin@example.com",
    "lista_perfil": ["admin"],
    "lista_permission": ["*"]
  }
}
```

#### Resposta de Erro

```json
{
  "error": "invalid_grant",
  "error_description": "Invalid username or password"
}
```

### 2. Autenticação com Client Credentials

#### Requisição

```bash
curl -X POST http://localhost:2301/authorize \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=meu_app" \
  -d "client_secret=secret_key_123" \
  -d "scope=user_db"
```

#### Resposta

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "user_db"
}
```

### 3. Renovar Token com Refresh Token

#### Requisição

```bash
curl -X POST http://localhost:2301/authorize \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=8xLOxBtZp8..."
```

#### Resposta

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "9yMPyCuAq9...",
  "scope": "user_db user_fs"
}
```

### 4. Consumir API Protegida

#### Requisição

```bash
curl -X GET http://localhost:2301/api/users \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

#### Resposta de Sucesso

```json
{
  "items": [
    {"id": 1, "name": "João Silva", "email": "joao@example.com"},
    {"id": 2, "name": "Maria Santos", "email": "maria@example.com"}
  ]
}
```

#### Resposta de Erro (Token Inválido)

```json
{
  "error": "invalid_token",
  "error_description": "The access token provided is invalid"
}
```

#### Resposta de Erro (Token Expirado)

```json
{
  "error": "token_expired",
  "error_description": "The access token has expired"
}
```

### 5. Revogar Token

#### Requisição

```bash
curl -X POST http://localhost:2301/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -d "token_type_hint=access_token"
```

#### Resposta

```json
{
  "status": "revoked"
}
```

---

## Exemplos Avançados

### 1. Script Bash para Autenticação Automática

```bash
#!/bin/bash

# Configurações
BASE_URL="http://localhost:2301"
USERNAME="admin"
PASSWORD="senha123"
TOKEN_FILE="/tmp/ems_token.json"

# Função para obter token
get_token() {
    curl -s -X POST "$BASE_URL/authorize" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=password" \
      -d "username=$USERNAME" \
      -d "password=$PASSWORD" \
      -d "scope=user_db user_fs" \
      > "$TOKEN_FILE"
    
    if [ $? -eq 0 ]; then
        echo "✓ Token obtido com sucesso"
        cat "$TOKEN_FILE" | jq -r '.access_token'
    else
        echo "✗ Erro ao obter token"
        exit 1
    fi
}

# Função para consumir API
call_api() {
    local endpoint=$1
    local token=$(cat "$TOKEN_FILE" | jq -r '.access_token')
    
    curl -s -X GET "$BASE_URL$endpoint" \
      -H "Authorization: Bearer $token"
}

# Uso
TOKEN=$(get_token)
echo "Token: $TOKEN"

# Consumir API
call_api "/api/users" | jq '.'
```

### 2. Python com Requests

```python
import requests
from datetime import datetime, timedelta

class EMSBusClient:
    def __init__(self, base_url, username, password):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.access_token = None
        self.refresh_token = None
        self.token_expiry = None
    
    def authenticate(self):
        """Obtém access token"""
        response = requests.post(
            f"{self.base_url}/authorize",
            data={
                "grant_type": "password",
                "username": self.username,
                "password": self.password,
                "scope": "user_db user_fs"
            }
        )
        
        if response.status_code == 200:
            data = response.json()
            self.access_token = data["access_token"]
            self.refresh_token = data["refresh_token"]
            self.token_expiry = datetime.now() + timedelta(seconds=data["expires_in"])
            return True
        return False
    
    def refresh(self):
        """Renova access token"""
        response = requests.post(
            f"{self.base_url}/authorize",
            data={
                "grant_type": "refresh_token",
                "refresh_token": self.refresh_token
            }
        )
        
        if response.status_code == 200:
            data = response.json()
            self.access_token = data["access_token"]
            self.refresh_token = data["refresh_token"]
            self.token_expiry = datetime.now() + timedelta(seconds=data["expires_in"])
            return True
        return False
    
    def is_token_valid(self):
        """Verifica se token ainda é válido"""
        if not self.access_token or not self.token_expiry:
            return False
        return datetime.now() < self.token_expiry
    
    def get(self, endpoint):
        """Faz requisição GET autenticada"""
        if not self.is_token_valid():
            if not self.refresh():
                self.authenticate()
        
        response = requests.get(
            f"{self.base_url}{endpoint}",
            headers={"Authorization": f"Bearer {self.access_token}"}
        )
        return response.json()

# Uso
client = EMSBusClient("http://localhost:2301", "admin", "senha123")
client.authenticate()
users = client.get("/api/users")
print(users)
```

### 3. JavaScript/Node.js

```javascript
const axios = require('axios');

class EMSBusClient {
    constructor(baseUrl, username, password) {
        this.baseUrl = baseUrl;
        this.username = username;
        this.password = password;
        this.accessToken = null;
        this.refreshToken = null;
    }

    async authenticate() {
        const params = new URLSearchParams();
        params.append('grant_type', 'password');
        params.append('username', this.username);
        params.append('password', this.password);
        params.append('scope', 'user_db user_fs');

        const response = await axios.post(`${this.baseUrl}/authorize`, params);
        
        this.accessToken = response.data.access_token;
        this.refreshToken = response.data.refresh_token;
        
        return this.accessToken;
    }

    async get(endpoint) {
        if (!this.accessToken) {
            await this.authenticate();
        }

        try {
            const response = await axios.get(`${this.baseUrl}${endpoint}`, {
                headers: {
                    'Authorization': `Bearer ${this.accessToken}`
                }
            });
            return response.data;
        } catch (error) {
            if (error.response?.status === 401) {
                // Token expirado, renovar
                await this.refresh();
                return this.get(endpoint);
            }
            throw error;
        }
    }

    async refresh() {
        const params = new URLSearchParams();
        params.append('grant_type', 'refresh_token');
        params.append('refresh_token', this.refreshToken);

        const response = await axios.post(`${this.baseUrl}/authorize`, params);
        
        this.accessToken = response.data.access_token;
        this.refreshToken = response.data.refresh_token;
    }
}

// Uso
(async () => {
    const client = new EMSBusClient('http://localhost:2301', 'admin', 'senha123');
    await client.authenticate();
    const users = await client.get('/api/users');
    console.log(users);
})();
```

---

## Troubleshooting

### Erro: "invalid_grant"

**Causa:** Credenciais inválidas (username/password incorretos)

**Solução:**
```bash
# Verificar usuário existe
curl http://localhost:2301/api/users?filter=login:admin

# Verificar logs do barramento
docker logs ems-bus | grep -i "invalid_grant"
```

### Erro: "invalid_client"

**Causa:** Client ID ou Client Secret incorretos

**Solução:**
```bash
# Verificar cliente cadastrado
curl http://localhost:2301/api/clients?filter=client_id:meu_app
```

### Erro: "token_expired"

**Causa:** Access token expirou

**Solução:**
```bash
# Usar refresh token para renovar
curl -X POST http://localhost:2301/authorize \
  -d "grant_type=refresh_token" \
  -d "refresh_token=SEU_REFRESH_TOKEN"
```

### Erro: "insufficient_scope"

**Causa:** Token não possui scope necessário para acessar o recurso

**Solução:**
```bash
# Solicitar token com scopes corretos
curl -X POST http://localhost:2301/authorize \
  -d "grant_type=password" \
  -d "username=admin" \
  -d "password=senha123" \
  -d "scope=user_db user_fs admin"
```

### Debug de Tokens

```bash
# Decodificar JWT (sem validar assinatura)
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." | \
  cut -d'.' -f2 | \
  base64 -d 2>/dev/null | \
  jq '.'
```

---

## Boas Práticas

### 1. Segurança

✅ **SEMPRE use HTTPS em produção**
```bash
# Produção
curl https://api.example.com/authorize

# Desenvolvimento (apenas)
curl http://localhost:2301/authorize
```

✅ **Armazene tokens de forma segura**
- Nunca commite tokens no Git
- Use variáveis de ambiente ou secrets managers
- Criptografe tokens em repouso

✅ **Implemente renovação automática de tokens**
```python
# Bom: Renova automaticamente
if token_expired():
    refresh_token()

# Ruim: Falha quando token expira
make_api_call()  # Pode falhar se token expirado
```

✅ **Revogue tokens quando não forem mais necessários**
```bash
# Ao fazer logout
curl -X POST http://localhost:2301/revoke \
  -d "token=$ACCESS_TOKEN"
```

### 2. Performance

✅ **Reutilize tokens enquanto válidos**
```python
# Bom: Verifica validade antes de renovar
if not is_token_valid():
    refresh_token()

# Ruim: Solicita novo token a cada chamada
authenticate()  # Desnecessário se token ainda válido
```

✅ **Use refresh tokens para sessões longas**
```bash
# Evita re-autenticação com username/password
curl -X POST /authorize -d "grant_type=refresh_token" -d "refresh_token=..."
```

### 3. Monitoramento

✅ **Monitore expiração de tokens**
```bash
# Alerta quando token está próximo de expirar
if [ $((EXPIRY - NOW)) -lt 300 ]; then
    echo "Token expira em menos de 5 minutos!"
    refresh_token
fi
```

✅ **Log de autenticações**
```bash
# Registre tentativas de autenticação
echo "$(date) - Autenticação bem-sucedida para $USERNAME" >> auth.log
```

### 4. Desenvolvimento

✅ **Use diferentes scopes para diferentes ambientes**
```bash
# Desenvolvimento
scope="user_db user_fs debug"

# Produção
scope="user_db user_fs"
```

✅ **Documente os scopes necessários**
```yaml
# API Documentation
/api/users:
  required_scopes: ["user_db"]
  
/api/admin/users:
  required_scopes: ["user_db", "admin"]
```

---

## Referências

- [RFC 6749 - OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 6750 - OAuth 2.0 Bearer Token Usage](https://tools.ietf.org/html/rfc6750)
- [JWT.io - JSON Web Tokens](https://jwt.io/)
- [ems-bus README](../README.md)

---

## Apêndice

### Códigos de Erro OAuth2

| Código | Descrição | Ação |
|--------|-----------|------|
| `invalid_request` | Parâmetros inválidos ou faltando | Verificar requisição |
| `invalid_client` | Client ID/Secret inválidos | Verificar credenciais do cliente |
| `invalid_grant` | Username/Password inválidos | Verificar credenciais do usuário |
| `unauthorized_client` | Cliente não autorizado para este grant type | Verificar configuração do cliente |
| `unsupported_grant_type` | Grant type não suportado | Usar grant type válido |
| `invalid_scope` | Scope inválido ou não permitido | Verificar scopes disponíveis |
| `token_expired` | Token expirou | Renovar com refresh token |
| `insufficient_scope` | Token não possui permissões necessárias | Solicitar token com scopes corretos |

### Scopes Padrão

| Scope | Descrição |
|-------|-----------|
| `user_db` | Acesso a usuários do banco de dados |
| `user_fs` | Acesso a usuários do filesystem |
| `admin` | Acesso administrativo |
| `read` | Apenas leitura |
| `write` | Leitura e escrita |

---

**Última atualização:** 2026-01-17  
**Versão do documento:** 1.0  
**Autor:** Equipe ems-bus
