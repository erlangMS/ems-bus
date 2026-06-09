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

```
# HELP emsbus_http_requests_seconds HTTP request latency in seconds
# TYPE emsbus_http_requests_seconds histogram
emsbus_http_requests_seconds_bucket{method="GET",uri="/api/v1/pessoas",status="200",le="0.005"} 312
emsbus_http_requests_seconds_bucket{method="GET",uri="/api/v1/pessoas",status="200",le="0.01"}  450
emsbus_http_requests_seconds_bucket{method="GET",uri="/api/v1/pessoas",status="200",le="0.025"} 612
emsbus_http_requests_seconds_bucket{method="GET",uri="/api/v1/pessoas",status="200",le="0.05"}  720
emsbus_http_requests_seconds_bucket{method="GET",uri="/api/v1/pessoas",status="200",le="0.1"}   780
emsbus_http_requests_seconds_bucket{method="GET",uri="/api/v1/pessoas",status="200",le="0.25"}  800
emsbus_http_requests_seconds_bucket{method="GET",uri="/api/v1/pessoas",status="200",le="0.5"}   800
emsbus_http_requests_seconds_bucket{method="GET",uri="/api/v1/pessoas",status="200",le="1.0"}   800
emsbus_http_requests_seconds_bucket{method="GET",uri="/api/v1/pessoas",status="200",le="2.5"}   800
emsbus_http_requests_seconds_bucket{method="GET",uri="/api/v1/pessoas",status="200",le="5.0"}   800
emsbus_http_requests_seconds_bucket{method="GET",uri="/api/v1/pessoas",status="200",le="10.0"}  800
emsbus_http_requests_seconds_bucket{method="GET",uri="/api/v1/pessoas",status="200",le="+Inf"}  800
emsbus_http_requests_seconds_count{method="GET",uri="/api/v1/pessoas",status="200"} 800
emsbus_http_requests_seconds_sum{method="GET",uri="/api/v1/pessoas",status="200"}   4.123456
# HELP emsbus_result_cache_requests_total Total result cache lookups by result
# TYPE emsbus_result_cache_requests_total counter
emsbus_result_cache_requests_total{result="hit"}  640
emsbus_result_cache_requests_total{result="miss"} 160
# HELP emsbus_log_events_total Total log events by level
# TYPE emsbus_log_events_total counter
emsbus_log_events_total{level="error"} 2
emsbus_log_events_total{level="warn"}  14
emsbus_log_events_total{level="info"}  3821
# HELP emsbus_worker_pool_workers Worker pool size by service and state
# TYPE emsbus_worker_pool_workers gauge
emsbus_worker_pool_workers{service="/api/v1/pessoas",state="idle"}     8
emsbus_worker_pool_workers{service="/api/v1/pessoas",state="overflow"} 0
emsbus_worker_pool_workers{service="/api/v1/pessoas",state="waiting"}  0
# HELP emsbus_catalog_services_total Number of registered services by HTTP method
# TYPE emsbus_catalog_services_total gauge
emsbus_catalog_services_total{method="GET"}    142
emsbus_catalog_services_total{method="POST"}    38
emsbus_catalog_services_total{method="PUT"}     21
emsbus_catalog_services_total{method="DELETE"}   9
emsbus_catalog_services_total{method="KERNEL"}  12
```

---

## Métricas disponíveis

### `emsbus_http_requests_seconds` (histogram)

Latência de cada requisição HTTP, em segundos, com labels de método, rota e status.

| Label    | Descrição                                                       | Exemplo                          |
|----------|-----------------------------------------------------------------|----------------------------------|
| `method` | Verbo HTTP                                                      | `GET`, `POST`, `PUT`, `DELETE`   |
| `uri`    | Padrão de URL do catálogo (não a URL real — evita alta cardinalidade) | `/api/v1/pessoas`, `/auth/token` |
| `status` | Código HTTP de resposta                                         | `200`, `401`, `404`, `500`       |

**Buckets (segundos):** `0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, +Inf`

Idênticos aos padrões do Micrometer para Spring Boot (`http.server.requests`).

Séries expostas por combinação de labels:
- `emsbus_http_requests_seconds_bucket{...,le="N"}` — contagem cumulativa até o bucket N
- `emsbus_http_requests_seconds_count{...}` — total de requisições
- `emsbus_http_requests_seconds_sum{...}` — soma das latências em segundos

---

### `emsbus_result_cache_requests_total` (counter)

Total de consultas ao cache de resultados (`result_cache`) do dispatcher.

| Label    | Descrição         | Valores          |
|----------|-------------------|------------------|
| `result` | Resultado do cache | `hit`, `miss`    |

---

### `emsbus_log_events_total` (counter)

Total de eventos de log emitidos desde o startup.

| Label   | Descrição     | Valores                    |
|---------|---------------|----------------------------|
| `level` | Nível do log  | `error`, `warn`, `info`    |

---

### `emsbus_odbc_pool_connections` (gauge)

Conexões ODBC ativas e ociosas por datasource — equivalente às métricas HikariCP do Spring Boot (`hikaricp.connections.active`, `.idle`).

| Label        | Descrição                       | Exemplo                       |
|--------------|---------------------------------|-------------------------------|
| `datasource` | Nome do datasource no catálogo  | `unb_db`, `sigrh_db`          |
| `state`      | Estado da conexão               | `active`, `idle`              |

- `active` — conexões atualmente em uso por uma requisição
- `idle` — conexões na fila do pool, prontas para reutilização

### `emsbus_odbc_pool_connections_max` (gauge)

Tamanho máximo (`max_pool_size`) configurado para cada datasource.

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
rate(emsbus_http_requests_seconds_count[5m])
```

Com agrupamento por rota:

```promql
sum by (uri, method)(
  rate(emsbus_http_requests_seconds_count[5m])
)
```

---

### Errors — Taxa de erros HTTP 4xx e 5xx

Taxa de erros 5xx por rota (percentual):

```promql
sum by (uri)(
  rate(emsbus_http_requests_seconds_count{status=~"5.."}[5m])
)
/
sum by (uri)(
  rate(emsbus_http_requests_seconds_count[5m])
) * 100
```

Taxa de erros 4xx:

```promql
sum by (uri, status)(
  rate(emsbus_http_requests_seconds_count{status=~"4.."}[5m])
)
```

Erros totais 4xx + 5xx:

```promql
sum(rate(emsbus_http_requests_seconds_count{status=~"[45].."}[5m]))
```

---

### Duration — Percentis de latência

Latência p99 global:

```promql
histogram_quantile(0.99,
  sum by (le)(
    rate(emsbus_http_requests_seconds_bucket[5m])
  )
)
```

Latência p50, p95, p99 por rota (painel multi-linha):

```promql
histogram_quantile(0.99,
  sum by (le, uri)(
    rate(emsbus_http_requests_seconds_bucket[5m])
  )
)
```

Latência média por rota:

```promql
sum by (uri)(
  rate(emsbus_http_requests_seconds_sum[5m])
)
/
sum by (uri)(
  rate(emsbus_http_requests_seconds_count[5m])
)
```

Latência p99 apenas para erros 5xx:

```promql
histogram_quantile(0.99,
  sum by (le, uri)(
    rate(emsbus_http_requests_seconds_bucket{status=~"5.."}[5m])
  )
)
```

---

### Cache — Hit ratio do result_cache

```promql
rate(emsbus_result_cache_requests_total{result="hit"}[5m])
/
rate(emsbus_result_cache_requests_total[5m])
* 100
```

Hit ratio abaixo de 80% pode indicar TTL muito curto no `result_cache`:

```promql
(
  rate(emsbus_result_cache_requests_total{result="hit"}[5m])
  /
  rate(emsbus_result_cache_requests_total[5m])
) < 0.8
```

---

### ODBC Pool — Saturação de conexões com banco

Conexões ativas por datasource:

```promql
emsbus_odbc_pool_connections{state="active"}
```

Percentual de utilização do pool (pressão sobre o banco):

```promql
emsbus_odbc_pool_connections{state="active"}
/
emsbus_odbc_pool_connections_max
* 100
```

Alerta: pool acima de 80% de utilização:

```promql
(
  emsbus_odbc_pool_connections{state="active"}
  /
  emsbus_odbc_pool_connections_max
) > 0.8
```

Conexões idle (eficiência do pool — idle = 0 e active = max indica pool esgotado):

```promql
emsbus_odbc_pool_connections{state="idle"}
```

---

### Log Errors — Spike de erros

Taxa de logs de erro por segundo:

```promql
rate(emsbus_log_events_total{level="error"}[1m])
```

Alerta: mais de 5 erros/s nos últimos 2 minutos:

```promql
rate(emsbus_log_events_total{level="error"}[2m]) > 5
```

---

### Alertas recomendados

```yaml
groups:
  - name: emsbus
    rules:
      - alert: EmsbuHighErrorRate
        expr: |
          sum(rate(emsbus_http_requests_seconds_count{status=~"5.."}[5m]))
          /
          sum(rate(emsbus_http_requests_seconds_count[5m])) > 0.05
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "ems-bus error rate above 5%"

      - alert: EmsbuHighLatency
        expr: |
          histogram_quantile(0.99,
            sum by (le)(rate(emsbus_http_requests_seconds_bucket[5m]))
          ) > 2.0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "ems-bus p99 latency above 2s"

      - alert: EmsbuOdbcPoolSaturated
        expr: |
          (emsbus_odbc_pool_connections{state="active"}
          / emsbus_odbc_pool_connections_max) > 0.8
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "ODBC pool above 80% capacity for {{ $labels.datasource }}"

      - alert: EmsbuLogErrorSpike
        expr: rate(emsbus_log_events_total{level="error"}[2m]) > 5
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "ems-bus logging more than 5 errors/s"
```

---

## Arquitetura da implementação

| Módulo | Papel |
|--------|-------|
| [src/util/ems_http_metrics.erl](../src/util/ems_http_metrics.erl) | Tabelas ETS de contadores atômicos; API `observe/4`, `inc_cache_hit/0`, `inc_cache_miss/0`, `inc_log/1` |
| [src/service/ems_prometheus_service.erl](../src/service/ems_prometheus_service.erl) | Handler do endpoint `/metrics`; coleta e formata texto Prometheus. Pool ODBC via `mnesia:dirty_all_keys(service_datasource)` + `ems_odbc_pool:connection_pool_size/1` |
| [src/http/ems_http_handler.erl](../src/http/ems_http_handler.erl) | Hook `ems_http_metrics:observe/4` nos dois branches pós-dispatch |
| [src/distpatcher/ems_dispatcher.erl](../src/distpatcher/ems_dispatcher.erl) | Hooks `inc_cache_hit/0` e `inc_cache_miss/0` em `check_result_cache/5` |
| [src/util/ems_logger.erl](../src/util/ems_logger.erl) | Hook `inc_log/1` em `write_msg/2` (captura todos os níveis) |

**Impacto de performance:**
- ~3 µs de overhead por requisição (≈16 chamadas NIF `ets:update_counter` @200ns cada)
- ~6 MB de memória ETS off-heap no pior caso (200 rotas × 4 métodos × 6 status × 15 entradas)
- Coleta de métricas ocorre apenas no scrape (a cada 15–30s pelo Prometheus)
- Sem dependências externas adicionadas ao projeto
