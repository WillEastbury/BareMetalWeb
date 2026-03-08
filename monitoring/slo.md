# BareMetalWeb — Service Level Objectives

| SLI | SLO Target | Measurement | Alert Threshold |
|-----|-----------|-------------|-----------------|
| **Availability** | 99.9% (8.7 h downtime/year) | `/health` probe success rate | Health failure > 2 min |
| **Latency (P95)** | < 500 ms | `bmw_http_request_duration_seconds{quantile="0.95"}` | > 1 s for 10 min |
| **Latency (P99)** | < 2 s | `bmw_http_request_duration_seconds{quantile="0.99"}` | > 5 s for 5 min |
| **Error rate** | < 1% of requests | `bmw_http_requests_errors_total / bmw_http_requests_total` | > 5% for 5 min |
| **Data durability** | 99.99% | WAL write success rate (`bmw_wal_appends_total`) | WAL append failures > 0 |

## Error Budget

At 99.9% availability the monthly error budget is **43.2 minutes**.
Burn-rate alerting fires when the budget would be exhausted within 1 hour (critical)
or within 6 hours (warning).

## Measurement

All SLIs are derived from the Prometheus metrics exposed at `/metrics/prometheus`.
The alert rules in `monitoring/prometheus-alerts.yml` encode these thresholds.
