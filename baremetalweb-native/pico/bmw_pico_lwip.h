/* bmw_pico_lwip.h — lwIP raw-API adapter for BareMetalWeb on Pico 2W
 *
 * Replaces BSD sockets with lwIP tcp_* callbacks. Provides the same
 * http_conn_t / event-driven model but using raw lwIP PCBs.
 */
#ifndef BMW_PICO_LWIP_H
#define BMW_PICO_LWIP_H

#include "pico/stdlib.h"
#include "lwip/tcp.h"
#include "lwip/pbuf.h"
#include "bmw_embedded_files.h"

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

/* ---- Tuning (matches baremetalweb-native sizes) ---- */
#define BMW_PICO_MAX_CONN     4
#define BMW_PICO_READ_BUF     2048
#define BMW_PICO_WRITE_BUF    4096   /* lwIP MSS-limited; we chunk via tcp_sndbuf */
#define BMW_PICO_MAX_HEADERS  12
#define BMW_PICO_MAX_PATH     128
#define BMW_PICO_MAX_ROUTES   24
#define BMW_PICO_HTTP_PORT    80

/* ---- Minimal HTTP request/response types ---- */
typedef struct {
    char name[32];
    char value[256];
} bmw_pico_header_t;

typedef struct {
    char method[8];
    char path[BMW_PICO_MAX_PATH];
    char query[128];
    bmw_pico_header_t headers[BMW_PICO_MAX_HEADERS];
    int header_count;
    const char *body;
    size_t body_len;
    bool keep_alive;
} bmw_pico_request_t;

typedef struct {
    int status;
    bmw_pico_header_t headers[8];
    int header_count;
    const uint8_t *body;
    size_t body_len;
    bool body_is_static;  /* true = pointer into flash, don't free */
} bmw_pico_response_t;

/* ---- Route handler ---- */
typedef int (*bmw_pico_route_handler_t)(bmw_pico_request_t *req, bmw_pico_response_t *resp, void *ctx);

typedef struct {
    char prefix[BMW_PICO_MAX_PATH];
    bmw_pico_route_handler_t handler;
    void *ctx;
    bool exact;
} bmw_pico_route_t;

/* ---- Connection state ---- */
typedef enum { PCONN_IDLE = 0, PCONN_READING, PCONN_WRITING } pico_conn_state_t;

typedef struct {
    struct tcp_pcb *pcb;
    pico_conn_state_t state;
    uint8_t read_buf[BMW_PICO_READ_BUF];
    uint16_t read_pos;
    bool in_use;
    bool keep_alive;
    uint16_t bytes_in_flight;
    /* Dynamic response body (malloc'd, needs free after send) */
    uint8_t *dyn_body;
    /* Unsent body tracking for chunked resume */
    const uint8_t *pending_body;
    size_t pending_body_len;
    size_t pending_body_sent;
    bool pending_is_static;
    uint16_t poll_count; /* idle poll counter for timeout */
} bmw_pico_conn_t;

/* ---- Server context ---- */
typedef struct {
    struct tcp_pcb *listen_pcb;
    bmw_pico_conn_t conns[BMW_PICO_MAX_CONN];
    bmw_pico_route_t routes[BMW_PICO_MAX_ROUTES];
    int route_count;
} bmw_pico_server_t;

/* ---- API ---- */
void bmw_pico_server_init(bmw_pico_server_t *srv);
bool bmw_pico_server_start(bmw_pico_server_t *srv, uint16_t port);
void bmw_pico_add_route(bmw_pico_server_t *srv, const char *prefix, bool exact,
                        bmw_pico_route_handler_t handler, void *ctx);

/* Built-in: serves embedded files */
int bmw_pico_static_handler(bmw_pico_request_t *req, bmw_pico_response_t *resp, void *ctx);

/* Response helpers */
void bmw_pico_resp_set_body(bmw_pico_response_t *resp, const uint8_t *data, size_t len, bool is_static);
void bmw_pico_resp_add_header(bmw_pico_response_t *resp, const char *name, const char *value);

#endif
