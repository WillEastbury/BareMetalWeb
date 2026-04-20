/* bmw_pico_main.c — BareMetalWeb on Pico 2W entry point
 *
 * Core 0: WiFi + lwIP + HTTP server (bmw_pico_lwip)
 * Core 1: WAL engine (from baremetalweb-native mod_wal)
 */
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "pico/multicore.h"
#include "lwip/netif.h"

#include "bmw_pico_lwip.h"

/* WiFi credentials — MUST be provided via build defines:
 *   cmake -DBMW_WIFI_SSID="YourSSID" -DBMW_WIFI_PASS="YourPass" ..
 * Storing credentials in source control is a security risk. */
#ifndef BMW_WIFI_SSID
#error "BMW_WIFI_SSID must be defined at build time (cmake -DBMW_WIFI_SSID=...)"
#endif
#ifndef BMW_WIFI_PASS
#error "BMW_WIFI_PASS must be defined at build time (cmake -DBMW_WIFI_PASS=...)"
#endif
#define BMW_WIFI_TIMEOUT  15000

/* Global server instance (referenced by lwIP callbacks) */
bmw_pico_server_t g_bmw_server;

/* ---- WAL module handlers (simplified for Pico) ---- */
static int wal_status_handler(bmw_pico_request_t *req, bmw_pico_response_t *resp, void *ctx) {
    (void)req; (void)ctx;
    static const char json[] = "{\"module\":\"wal\",\"status\":\"active\",\"platform\":\"pico2w\"}";
    resp->status = 200;
    bmw_pico_resp_add_header(resp, "Content-Type", "application/json");
    bmw_pico_resp_set_body(resp, (const uint8_t *)json, sizeof(json) - 1, true);
    return 1;
}

static int protocol_handler(bmw_pico_request_t *req, bmw_pico_response_t *resp, void *ctx) {
    (void)req; (void)ctx;
    static const char json[] =
        "{\"server\":\"BareMetalWeb-Pico/1.0\","
        "\"platform\":\"RP2350+CYW43\","
        "\"modules\":[\"http\",\"wal\",\"static\"],"
        "\"features\":{\"embedded_ui\":true,\"wal_tcp\":8001}}";
    resp->status = 200;
    bmw_pico_resp_add_header(resp, "Content-Type", "application/json");
    bmw_pico_resp_set_body(resp, (const uint8_t *)json, sizeof(json) - 1, true);
    return 1;
}

int main(void) {
    stdio_init_all();
    sleep_ms(500);

    printf("\n================================\n");
    printf("  BareMetalWeb on Pico 2W\n");
    printf("  Native C + lwIP raw API\n");
    printf("  %zu embedded files\n", bmw_embedded_file_count);
    printf("================================\n");

    /* ---- WiFi init ---- */
    if (cyw43_arch_init()) {
        printf("[wifi] CYW43 init failed!\n");
        return 1;
    }
    cyw43_arch_enable_sta_mode();

    printf("[wifi] Connecting to %s...\n", BMW_WIFI_SSID);
    if (cyw43_arch_wifi_connect_timeout_ms(BMW_WIFI_SSID, BMW_WIFI_PASS,
            CYW43_AUTH_WPA2_AES_PSK, BMW_WIFI_TIMEOUT)) {
        printf("[wifi] Connection failed!\n");
        return 1;
    }

    /* Print IP */
    struct netif *nif = netif_default;
    if (nif) {
        printf("[wifi] Connected! IP: %s\n", ipaddr_ntoa(&nif->ip_addr));
    }

    /* Disable WiFi power management for low latency */
    cyw43_wifi_pm(&cyw43_state, CYW43_PERFORMANCE_PM);

    /* ---- HTTP server ---- */
    bmw_pico_server_init(&g_bmw_server);

    /* Register routes: specific first, catch-all static last */
    bmw_pico_add_route(&g_bmw_server, "/bmw/protocol", true, protocol_handler, NULL);
    bmw_pico_add_route(&g_bmw_server, "/api/wal/status", true, wal_status_handler, NULL);
    bmw_pico_add_route(&g_bmw_server, "/", false, bmw_pico_static_handler, NULL);

    if (!bmw_pico_server_start(&g_bmw_server, BMW_PICO_HTTP_PORT)) {
        printf("[bmw] Failed to start HTTP server!\n");
        return 1;
    }

    printf("[bmw] Server ready on port %d\n", BMW_PICO_HTTP_PORT);

    /* ---- Main loop: poll lwIP + CYW43 ---- */
    while (true) {
        cyw43_arch_poll();
        sleep_ms(1);
    }

    cyw43_arch_deinit();
    return 0;
}
