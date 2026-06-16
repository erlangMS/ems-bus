# Métricas Prometheus do ems-bus

O ems-bus expõe métricas RED (Rate, Errors, Duration) no endpoint `GET /metrics`, compatível com o formato Prometheus text 0.0.4 e dashboards Grafana.

---

## Endpoint

```
GET /metrics
Content-Type: text/plain; version=0.0.4; charset=utf-8
Authorization: public (sem autenticação)
```

### Exemplo de resposta

Capturado a partir de `https://servicos.desenv.unb.br/metrics` em 2026-06-10, após uma bateria de testes (autenticação OAuth2 e bind LDAP com credenciais inválidas, e uma requisição a uma URL na denylist para acionar o tarpit hard). O bloco do histograma abaixo mostra apenas 3 das ~13 combinações `method`/`uri`/`status`/`exception` observadas, escolhidas para ilustrar uma rota de sucesso de alto tráfego, um erro de autenticação e um erro com alta latência; as demais foram omitidas por brevidade.

```
# HELP http_server_requests_seconds HTTP request latency in seconds
# TYPE http_server_requests_seconds histogram
http_server_requests_seconds_bucket{application="app-ems-bus",method="GET",uri="/metrics",status="200",exception="None",le="0.05"} 22
http_server_requests_seconds_bucket{application="app-ems-bus",method="GET",uri="/metrics",status="200",exception="None",le="0.1"}  22
http_server_requests_seconds_bucket{application="app-ems-bus",method="GET",uri="/metrics",status="200",exception="None",le="0.2"}  22
http_server_requests_seconds_bucket{application="app-ems-bus",method="GET",uri="/metrics",status="200",exception="None",le="0.3"}  22
http_server_requests_seconds_bucket{application="app-ems-bus",method="GET",uri="/metrics",status="200",exception="None",le="0.5"}  22
http_server_requests_seconds_bucket{application="app-ems-bus",method="GET",uri="/metrics",status="200",exception="None",le="1.0"}  22
http_server_requests_seconds_bucket{application="app-ems-bus",method="GET",uri="/metrics",status="200",exception="None",le="+Inf"} 22
http_server_requests_seconds_count{application="app-ems-bus",method="GET",uri="/metrics",status="200",exception="None"} 22
http_server_requests_seconds_sum{application="app-ems-bus",method="GET",uri="/metrics",status="200",exception="None"}   0.055000
http_server_requests_seconds_bucket{application="app-ems-bus",method="POST",uri="/authorize",status="401",exception="access_denied",le="0.05"} 1
http_server_requests_seconds_bucket{application="app-ems-bus",method="POST",uri="/authorize",status="401",exception="access_denied",le="0.1"}  1
http_server_requests_seconds_bucket{application="app-ems-bus",method="POST",uri="/authorize",status="401",exception="access_denied",le="0.2"}  1
http_server_requests_seconds_bucket{application="app-ems-bus",method="POST",uri="/authorize",status="401",exception="access_denied",le="0.3"}  1
http_server_requests_seconds_bucket{application="app-ems-bus",method="POST",uri="/authorize",status="401",exception="access_denied",le="0.5"}  1
http_server_requests_seconds_bucket{application="app-ems-bus",method="POST",uri="/authorize",status="401",exception="access_denied",le="1.0"}  1
http_server_requests_seconds_bucket{application="app-ems-bus",method="POST",uri="/authorize",status="401",exception="access_denied",le="+Inf"} 1
http_server_requests_seconds_count{application="app-ems-bus",method="POST",uri="/authorize",status="401",exception="access_denied"} 1
http_server_requests_seconds_sum{application="app-ems-bus",method="POST",uri="/authorize",status="401",exception="access_denied"}   0.002000
http_server_requests_seconds_bucket{application="app-ems-bus",method="GET",uri="/(?<name>.+)/barramento",status="409",exception="einvalid_client_barramento",le="0.05"} 0
http_server_requests_seconds_bucket{application="app-ems-bus",method="GET",uri="/(?<name>.+)/barramento",status="409",exception="einvalid_client_barramento",le="0.1"}  0
http_server_requests_seconds_bucket{application="app-ems-bus",method="GET",uri="/(?<name>.+)/barramento",status="409",exception="einvalid_client_barramento",le="0.2"}  0
http_server_requests_seconds_bucket{application="app-ems-bus",method="GET",uri="/(?<name>.+)/barramento",status="409",exception="einvalid_client_barramento",le="0.3"}  0
http_server_requests_seconds_bucket{application="app-ems-bus",method="GET",uri="/(?<name>.+)/barramento",status="409",exception="einvalid_client_barramento",le="0.5"}  0
http_server_requests_seconds_bucket{application="app-ems-bus",method="GET",uri="/(?<name>.+)/barramento",status="409",exception="einvalid_client_barramento",le="1.0"}  0
http_server_requests_seconds_bucket{application="app-ems-bus",method="GET",uri="/(?<name>.+)/barramento",status="409",exception="einvalid_client_barramento",le="+Inf"} 2
http_server_requests_seconds_count{application="app-ems-bus",method="GET",uri="/(?<name>.+)/barramento",status="409",exception="einvalid_client_barramento"} 2
http_server_requests_seconds_sum{application="app-ems-bus",method="GET",uri="/(?<name>.+)/barramento",status="409",exception="einvalid_client_barramento"}   60.004000
# ... demais combinações de method/uri/status/exception omitidas (/code_request, /authorize GET, /login/, /favicon.ico, /.well-known/oauth-authorization-server, /authorize POST 200) ...
# HELP cache_requests_total Total result cache lookups by result
# TYPE cache_requests_total counter
cache_requests_total{application="app-ems-bus",result="hit"}  22
cache_requests_total{application="app-ems-bus",result="miss"} 33
# HELP logback_events_total Total log events by level
# TYPE logback_events_total counter
logback_events_total{application="app-ems-bus",level="error"} 3
logback_events_total{application="app-ems-bus",level="warn"}  12
logback_events_total{application="app-ems-bus",level="info"}  514
# HELP auth_user_success_total Total successful OAuth2 user authentications
# TYPE auth_user_success_total counter
auth_user_success_total{application="app-ems-bus"} 1
# HELP auth_user_error_total Total failed OAuth2 user authentications
# TYPE auth_user_error_total counter
auth_user_error_total{application="app-ems-bus"} 1
# HELP ldap_user_success_total Total successful LDAP user authentications
# TYPE ldap_user_success_total counter
ldap_user_success_total{application="app-ems-bus"} 0
# HELP ldap_user_error_total Total failed LDAP user authentications
# TYPE ldap_user_error_total counter
ldap_user_error_total{application="app-ems-bus"} 1
# HELP rate_limit_total Total requests throttled by the rate limiter, by action
# TYPE rate_limit_total counter
rate_limit_total{application="app-ems-bus",action="tarpit"} 0
rate_limit_total{application="app-ems-bus",action="block"}  0
# HELP tarpit_total Total requests delayed by the tarpit defense mechanism, by severity
# TYPE tarpit_total counter
tarpit_total{application="app-ems-bus",type="leve"} 5
tarpit_total{application="app-ems-bus",type="hard"} 1
# HELP db_pool_connections Database connection pool size by datasource and state
# TYPE db_pool_connections gauge
db_pool_connections{application="app-ems-bus",datasource="sig_unb",state="active"} 0
db_pool_connections{application="app-ems-bus",datasource="sig_unb",state="idle"}   1
db_pool_connections{application="app-ems-bus",datasource="sig_unb",state="total"}  1
db_pool_connections{application="app-ems-bus",datasource="ds_ems_user_loader",state="active"} 0
db_pool_connections{application="app-ems-bus",datasource="ds_ems_user_loader",state="idle"}   3
db_pool_connections{application="app-ems-bus",datasource="ds_ems_user_loader",state="total"}  3
# HELP db_pool_connections_max Database connection pool maximum size by datasource
# TYPE db_pool_connections_max gauge
db_pool_connections_max{application="app-ems-bus",datasource="sig_unb"} 25
db_pool_connections_max{application="app-ems-bus",datasource="ds_ems_user_loader"} 25
# HELP emsbus_catalog_services_total Number of registered services by HTTP method
# TYPE emsbus_catalog_services_total gauge
emsbus_catalog_services_total{application="app-ems-bus",method="GET"}    350
emsbus_catalog_services_total{application="app-ems-bus",method="POST"}   115
emsbus_catalog_services_total{application="app-ems-bus",method="PUT"}     77
emsbus_catalog_services_total{application="app-ems-bus",method="DELETE"}  63
emsbus_catalog_services_total{application="app-ems-bus",method="KERNEL"}  25
```

Notas sobre os valores acima:
- `ldap_user_success_total` e `rate_limit_total` (ambas as ações) estão em `0` — são valores reais da instância no momento da captura, não placeholders. `rate_limit_total` exige sustentar mais de 120 req/s para ser acionado, o que não foi reproduzido no servidor compartilhado de desenvolvimento.
- `tarpit_total{type="hard"}` foi de `0` para `1` após uma única requisição a uma URL na denylist (`*.php`), que recebeu HTTP 409 com ~30s de atraso.
- `auth_user_error_total` e `ldap_user_error_total` foram de `0` para `1` após, respectivamente, um `POST /authorize` com `grant_type=password` e credenciais inválidas (HTTP 401 `access_denied`) e um bind LDAP simples com DN/senha inválidos (`ldap_bind: Insufficient access (50)`).

Todas as métricas trazem o label `application="app-ems-bus"`, identificando esta instância ao lado de outros serviços (ex.: `app-forum-api`) no mesmo Prometheus/Grafana.

---

## Métricas disponíveis

### `http_server_requests_seconds` (histogram)

Latência de cada requisição HTTP, em segundos, com labels de método, rota, status e exceção.

| Label         | Descrição                                                       | Exemplo                          |
|---------------|-------------------------------------------------------------------|----------------------------------|
| `application` | Nome da aplicação (constante, presente em todas as métricas)   | `app-ems-bus`                    |
| `method`      | Verbo HTTP                                                      | `GET`, `POST`, `PUT`, `DELETE`   |
| `uri`         | Padrão de URL do catálogo (não a URL real — evita alta cardinalidade) | `/api/v1/pessoas`, `/auth/token` |
| `status`      | Código HTTP de resposta                                         | `200`, `401`, `404`, `500`       |
| `exception`   | Razão interna do erro, ou `None` em caso de sucesso             | `None`, `access_denied`, `etimeout_service` |

**Buckets (segundos):** `0.05, 0.1, 0.2, 0.3, 0.5, 1.0, +Inf`

Mesmo SLO configurado para o `app-forum-api` (`http_server_requests_seconds`).

Séries expostas por combinação de labels:
- `http_server_requests_seconds_bucket{...,le="N"}` — contagem cumulativa até o bucket N
- `http_server_requests_seconds_count{...}` — total de requisições
- `http_server_requests_seconds_sum{...}` — soma das latências em segundos

---

### `cache_requests_total` (counter)

Total de consultas ao cache de resultados (`result_cache`) do dispatcher.

| Label    | Descrição         | Valores          |
|----------|-------------------|------------------|
| `result` | Resultado do cache | `hit`, `miss`    |

---

### `logback_events_total` (counter)

Total de eventos de log emitidos desde o startup.

| Label   | Descrição     | Valores                    |
|---------|---------------|----------------------------|
| `level` | Nível do log  | `error`, `warn`, `info`    |

---

### `auth_user_success_total` / `auth_user_error_total` (counter)

Total de autenticações de usuário via OAuth2 (`POST /token`, `/authorize`), incrementadas em `ems_oauth2_authorize:execute/1`. `success` conta emissões de access token (grant types `password`, `client_credentials`, `authorization_code`, `refresh_token`, passport); `error` conta falhas de autenticação/grant (`access_denied`) e exceções inesperadas. Sem labels adicionais além de `application`.

---

### `ldap_user_success_total` / `ldap_user_error_total` (counter)

Total de autenticações de usuário via LDAP bind (`ems_ldap_handler:handle_bind_request/7`). `success` conta binds aceitos (`resultCode = success`); `error` conta binds rejeitados (`invalidCredentials`, `insufficientAccessRights`). Sem labels adicionais além de `application`.

---

### `rate_limit_total` (counter)

Total de requisições contidas pelo rate limiter (`ems_rate_limiter:check/1`, em `ems_http_handler:init_rate_limit/2`).

| Label    | Descrição                                              | Valores           |
|----------|---------------------------------------------------------|-------------------|
| `action` | Ação aplicada ao exceder o limite configurado          | `tarpit`, `block` |

- `tarpit` — requisição atrasada (1s ou 5s, conforme o quanto o limite foi excedido) antes de prosseguir
- `block` — requisição rejeitada com HTTP 429 (limite excedido em mais de 2x)

---

### `tarpit_total` (counter)

Total de requisições atrasadas pelo mecanismo de tarpit (`ems_tarpit:tarpit_leve/0` e `tarpit_hard/0`), usado contra varreduras/URLs maliciosas e como fallback de erro genérico.

| Label  | Descrição                            | Valores         |
|--------|---------------------------------------|------------------|
| `type` | Severidade/duração do atraso aplicado | `leve`, `hard`   |

- `leve` — atraso curto (`?HTTP_TARPIT_SOFT_DELAY`, ex.: 2s) para serviço não encontrado e erros genéricos de request
- `hard` — atraso longo (`?HTTP_TARPIT_DELAY`, ex.: 30s) para URLs na denylist, URI muito longa ou método HTTP não suportado

---

### `db_pool_connections` (gauge)

Conexões ODBC por datasource — equivalente às métricas HikariCP do Spring Boot (`hikaricp.connections`, `.active`, `.idle`). Reportado apenas para datasources do tipo `postgresql` ou `sqlserver` (os tipos que usam o pool ODBC via `ems_odbc_pool`).

| Label        | Descrição                       | Exemplo                       |
|--------------|---------------------------------|-------------------------------|
| `datasource` | Nome do datasource no catálogo  | `unb_db`, `sig_unb`           |
| `state`      | Estado da conexão               | `active`, `idle`, `total`     |

- `active` — conexões atualmente em uso por uma requisição
- `idle` — conexões na fila do pool, prontas para reutilização
- `total` — total de conexões já criadas no pool (active + idle), equivalente a `hikaricp.connections`

### `db_pool_connections_max` (gauge)

Tamanho máximo (`max_pool_size`) **configurado** para cada datasource — equivalente a `hikaricp.connections.max` (valor estático de configuração, não um pico observado em runtime).

| Label        | Descrição                       |
|--------------|---------------------------------|
| `datasource` | Nome do datasource no catálogo  |

---

### `emsbus_catalog_services_total` (gauge)

Número de serviços registrados no catálogo por método HTTP. Útil para verificar se o catálogo carregou corretamente no startup.

| Label    | Valores                                        |
|----------|------------------------------------------------|
| `method` | `GET`, `POST`, `PUT`, `DELETE`, `KERNEL`       |

---

## Configuração do Prometheus

Adicione o ems-bus como target no `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'emsbus'
    scrape_interval: 15s
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: '/metrics'
```

Para múltiplas instâncias:

```yaml
scrape_configs:
  - job_name: 'emsbus'
    scrape_interval: 15s
    static_configs:
      - targets:
          - 'emsbus-01:9090'
          - 'emsbus-02:9090'
          - 'emsbus-03:9090'
    metrics_path: '/metrics'
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
        regex: '([^:]+).*'
        replacement: '$1'
```

---

## Queries PromQL para Grafana

### Rate — Throughput por rota (req/s)

```promql
rate(http_server_requests_seconds_count[5m])
```

Com agrupamento por rota:

```promql
sum by (uri, method)(
  rate(http_server_requests_seconds_count[5m])
)
```

---

### Errors — Taxa de erros HTTP 4xx e 5xx

Taxa de erros 5xx por rota (percentual):

```promql
sum by (uri)(
  rate(http_server_requests_seconds_count{status=~"5.."}[5m])
)
/
sum by (uri)(
  rate(http_server_requests_seconds_count[5m])
) * 100
```

Taxa de erros 4xx:

```promql
sum by (uri, status)(
  rate(http_server_requests_seconds_count{status=~"4.."}[5m])
)
```

Erros totais 4xx + 5xx:

```promql
sum(rate(http_server_requests_seconds_count{status=~"[45].."}[5m]))
```

---

### Duration — Percentis de latência

Latência p99 global:

```promql
histogram_quantile(0.99,
  sum by (le)(
    rate(http_server_requests_seconds_bucket[5m])
  )
)
```

Latência p50, p95, p99 por rota (painel multi-linha):

```promql
histogram_quantile(0.99,
  sum by (le, uri)(
    rate(http_server_requests_seconds_bucket[5m])
  )
)
```

Latência média por rota:

```promql
sum by (uri)(
  rate(http_server_requests_seconds_sum[5m])
)
/
sum by (uri)(
  rate(http_server_requests_seconds_count[5m])
)
```

Latência p99 apenas para erros 5xx:

```promql
histogram_quantile(0.99,
  sum by (le, uri)(
    rate(http_server_requests_seconds_bucket{status=~"5.."}[5m])
  )
)
```

---

### Cache — Hit ratio do result_cache

```promql
rate(cache_requests_total{result="hit"}[5m])
/
rate(cache_requests_total[5m])
* 100
```

Hit ratio abaixo de 80% pode indicar TTL muito curto no `result_cache`:

```promql
(
  rate(cache_requests_total{result="hit"}[5m])
  /
  rate(cache_requests_total[5m])
) < 0.8
```

---

### ODBC Pool — Saturação de conexões com banco

Conexões ativas por datasource:

```promql
db_pool_connections{state="active"}
```

Percentual de utilização do pool (pressão sobre o banco):

```promql
db_pool_connections{state="active"}
/
db_pool_connections_max
* 100
```

Alerta: pool acima de 80% de utilização:

```promql
(
  db_pool_connections{state="active"}
  /
  db_pool_connections_max
) > 0.8
```

Conexões idle (eficiência do pool — idle = 0 e active = max indica pool esgotado):

```promql
db_pool_connections{state="idle"}
```

---

### Log Errors — Spike de erros

Taxa de logs de erro por segundo:

```promql
rate(logback_events_total{level="error"}[1m])
```

Alerta: mais de 5 erros/s nos últimos 2 minutos:

```promql
rate(logback_events_total{level="error"}[2m]) > 5
```

---

### Auth — Taxa de erro de autenticação OAuth2 e LDAP

Taxa de erro de autenticação OAuth2 (percentual):

```promql
rate(auth_user_error_total[5m])
/
(rate(auth_user_success_total[5m]) + rate(auth_user_error_total[5m]))
* 100
```

Taxa de erro de bind LDAP (percentual):

```promql
rate(ldap_user_error_total[5m])
/
(rate(ldap_user_success_total[5m]) + rate(ldap_user_error_total[5m]))
* 100
```

---

### Rate Limit & Tarpit — Pressão de tráfego abusivo

Requisições bloqueadas (HTTP 429) por segundo:

```promql
rate(rate_limit_total{action="block"}[5m])
```

Requisições atrasadas (tarpit do rate limiter) por segundo:

```promql
rate(rate_limit_total{action="tarpit"}[5m])
```

Requisições atrasadas pelo tarpit de defesa (URLs maliciosas, scanners) por severidade:

```promql
sum by (type)(rate(tarpit_total[5m]))
```

---

### Alertas recomendados

```yaml
groups:
  - name: emsbus
    rules:
      - alert: EmsbuHighErrorRate
        expr: |
          sum(rate(http_server_requests_seconds_count{status=~"5.."}[5m]))
          /
          sum(rate(http_server_requests_seconds_count[5m])) > 0.05
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "ems-bus error rate above 5%"

      - alert: EmsbuHighLatency
        expr: |
          histogram_quantile(0.99,
            sum by (le)(rate(http_server_requests_seconds_bucket[5m]))
          ) > 2.0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "ems-bus p99 latency above 2s"

      - alert: EmsbuOdbcPoolSaturated
        expr: |
          (db_pool_connections{state="active"}
          / db_pool_connections_max) > 0.8
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "ODBC pool above 80% capacity for {{ $labels.datasource }}"

      - alert: EmsbuLogErrorSpike
        expr: rate(logback_events_total{level="error"}[2m]) > 5
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "ems-bus logging more than 5 errors/s"

      - alert: EmsbuAuthHighErrorRate
        expr: |
          rate(auth_user_error_total[5m])
          /
          (rate(auth_user_success_total[5m]) + rate(auth_user_error_total[5m])) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "ems-bus OAuth2 authentication error rate above 10%"

      - alert: EmsbuLdapHighErrorRate
        expr: |
          rate(ldap_user_error_total[5m])
          /
          (rate(ldap_user_success_total[5m]) + rate(ldap_user_error_total[5m])) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "ems-bus LDAP bind error rate above 10%"

      - alert: EmsbuRateLimitBlockSpike
        expr: rate(rate_limit_total{action="block"}[5m]) > 1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "ems-bus blocking more than 1 req/s due to rate limit"

      - alert: EmsbuTarpitHardSpike
        expr: rate(tarpit_total{type="hard"}[5m]) > 1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "ems-bus hard tarpit triggered more than 1 time/s (possible attack)"
```

---

## Arquitetura da implementação

| Módulo | Papel |
|--------|-------|
| [src/util/ems_http_metrics.erl](../src/util/ems_http_metrics.erl) | Tabelas ETS de contadores atômicos; API `observe/5`, `inc_cache_hit/0`, `inc_cache_miss/0`, `inc_log/1`, `inc_auth_success/0`, `inc_auth_error/0`, `inc_ldap_success/0`, `inc_ldap_error/0`, `inc_rate_limit/1`, `inc_tarpit/1` |
| [src/service/ems_prometheus_service.erl](../src/service/ems_prometheus_service.erl) | Handler do endpoint `/metrics`; coleta e formata texto Prometheus. Label `application="app-ems-bus"` aplicado a toda métrica via `format_sample/3`. Pool ODBC via `mnesia:dirty_all_keys(service_datasource)` (datasources `postgresql`/`sqlserver`) + `ems_odbc_pool:connection_pool_size/1` |
| [src/http/ems_http_handler.erl](../src/http/ems_http_handler.erl) | Hook `ems_http_metrics:observe/5` nos dois branches pós-dispatch; label `exception` derivado de `Request#request.reason` via `get_exception/1`. Hooks `inc_rate_limit/1` em `init_rate_limit/2` (`block`/`tarpit`) e `inc_tarpit(leve)` no fallback de erro genérico |
| [src/distpatcher/ems_dispatcher.erl](../src/distpatcher/ems_dispatcher.erl) | Hooks `inc_cache_hit/0` e `inc_cache_miss/0` em `check_result_cache/5` |
| [src/util/ems_logger.erl](../src/util/ems_logger.erl) | Hook `inc_log/1` em `write_msg/2` (captura todos os níveis) |
| [src/auth/ems_oauth2_authorize.erl](../src/auth/ems_oauth2_authorize.erl) | Hooks `inc_auth_success/0` e `inc_auth_error/0` em `execute/1` (emissão de access token, erro de grant/`access_denied` e exceções) |
| [src/ldap/ems_ldap_handler.erl](../src/ldap/ems_ldap_handler.erl) | Hooks `inc_ldap_success/0` e `inc_ldap_error/0` em `handle_bind_request/7` (resultCode `success` vs `invalidCredentials`/`insufficientAccessRights`) |
| [src/distpatcher/ems_encode_request.erl](../src/distpatcher/ems_encode_request.erl) | Hooks `inc_tarpit(hard)` para URL na denylist, URI muito longa e método HTTP não suportado; `inc_tarpit(leve)` para serviço não encontrado |

**Resiliência:**
- `observe/5` é a única função de métricas chamada incondicionalmente para toda requisição HTTP (em ambos os branches pós-dispatch de `ems_http_handler`), após a resposta já ter sido enviada via `cowboy_req:reply/4`. Por isso seu corpo inteiro roda em `try...catch _:_ -> ok end`, garantindo que nenhuma falha de coleta de métrica derrube o handler ou a conexão.
- Todas as `inc_*` (`inc_cache_hit/0`, `inc_log/1`, `inc_auth_success/0`, `inc_ldap_error/0`, `inc_rate_limit/1`, `inc_tarpit/1` etc.) seguem o mesmo padrão `catch ... , ok.`
- Em `ems_prometheus_service:execute/1`, cada família de métrica é coletada via `safe_collect/1` (`try Fun() catch _:_ -> [] end`), de forma que uma falha isolada (ex.: mnesia indisponível para o pool ODBC) omite apenas aquela família, sem derrubar o restante do scrape `/metrics`.
- Mesmo sem essas proteções, uma exceção em `execute/1` já seria contida pelo `try...catch` de `ems_dispatcher:dispatch_service_work/3`, que converte qualquer erro em uma resposta HTTP 500 isolada para aquela requisição — nunca propaga para o restante do barramento.

**Impacto de performance:**
- ~3 µs de overhead por requisição (≈16 chamadas NIF `ets:update_counter` @200ns cada)
- ~6 MB de memória ETS off-heap no pior caso (200 rotas × 4 métodos × 6 status × 15 entradas)
- Coleta de métricas ocorre apenas no scrape (a cada 15–30s pelo Prometheus)
- Sem dependências externas adicionadas ao projeto
