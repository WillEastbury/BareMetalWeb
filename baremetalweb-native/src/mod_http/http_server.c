/*
 * HTTP Server module - TCP listener, connection management, request dispatch
 */
#include "bmw_http.h"
#include "bmw_event_loop.h"
#include "bmw_wal.h"

#ifndef _WIN32
#include <errno.h>
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#endif

#ifdef _WIN32
#define BMW_SEND_FLAGS 0
#else
#define BMW_SEND_FLAGS MSG_NOSIGNAL
#endif

/* Declare the parse function from http_parser.c */
int bmw_http_parse_request(const char *buf, size_t len, bmw_request_t *req);

/* Connection state */
typedef enum {
    CONN_READING,
    CONN_WRITING,
    CONN_CLOSED
} conn_state_t;

typedef struct {
    bmw_socket_t fd;
    conn_state_t state;
    char read_buf[BMW_READ_BUF_SIZE];
    size_t read_pos;
    char write_buf[BMW_WRITE_BUF_SIZE];
    size_t write_pos;
    size_t write_len;
    bool keep_alive;
    time_t last_activity;
} http_conn_t;

/* HTTP module context */
typedef struct {
    bmw_socket_t listen_fd;
    bmw_event_loop_t *loop;
    bmw_router_t router;
    http_conn_t connections[BMW_MAX_CONNECTIONS];
    int conn_count;
    char static_root[256];
    uint16_t port;
    bmw_app_t *app; /* back-reference for dispatch */
} http_ctx_t;

/* Forward declarations */
static void http_on_accept(bmw_socket_t fd, int events, void *userdata);
static void http_on_conn_ready(bmw_socket_t fd, int events, void *userdata);
static int  http_send_response(http_conn_t *conn, bmw_response_t *resp);

/* Response helpers */
void bmw_response_init(bmw_response_t *resp) {
    memset(resp, 0, sizeof(*resp));
    resp->status = 200;
}

void bmw_response_set_status(bmw_response_t *resp, int status) {
    resp->status = status;
}

void bmw_response_add_header(bmw_response_t *resp, const char *name, const char *value) {
    if (resp->header_count >= BMW_MAX_HEADERS) return;
    bmw_header_t *h = &resp->headers[resp->header_count];
    snprintf(h->name, sizeof(h->name), "%s", name);
    snprintf(h->value, sizeof(h->value), "%s", value);
    resp->header_count++;
}

void bmw_response_set_body(bmw_response_t *resp, const char *body, size_t len) {
    if (resp->body) free(resp->body);
    resp->body = malloc(len);
    if (resp->body) {
        memcpy(resp->body, body, len);
        resp->body_len = len;
        resp->body_cap = len;
    }
}

void bmw_response_append_body(bmw_response_t *resp, const char *data, size_t len) {
    if (!resp->body) {
        resp->body_cap = len > 1024 ? len * 2 : 1024;
        resp->body = malloc(resp->body_cap);
        if (!resp->body) return;
        resp->body_len = 0;
    }
    if (resp->body_len + len > resp->body_cap) {
        resp->body_cap = (resp->body_len + len) * 2;
        char *new_buf = realloc(resp->body, resp->body_cap);
        if (!new_buf) return;
        resp->body = new_buf;
    }
    memcpy(resp->body + resp->body_len, data, len);
    resp->body_len += len;
}

void bmw_response_free(bmw_response_t *resp) {
    if (resp->body) { free(resp->body); resp->body = NULL; }
}

/* Status text lookup */
static const char *status_text(int code) {
    switch (code) {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 304: return "Not Modified";
        case 400: return "Bad Request";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 413: return "Payload Too Large";
        case 414: return "URI Too Long";
        case 500: return "Internal Server Error";
        case 503: return "Service Unavailable";
        default:  return "Unknown";
    }
}

static int http_send_response(http_conn_t *conn, bmw_response_t *resp) {
    /* First, compute how much body we can actually fit.
     * Reserve ~2KB for headers (generous upper bound). */
    size_t hdr_budget = 2048;
    size_t body_budget = BMW_WRITE_BUF_SIZE > hdr_budget ? BMW_WRITE_BUF_SIZE - hdr_budget : 0;
    size_t actual_body = resp->body_len < body_budget ? resp->body_len : body_budget;
    bool truncated = (actual_body < resp->body_len);

    /* If truncated, force connection close so client doesn't wait for more */
    if (truncated) conn->keep_alive = false;

    int n = snprintf(conn->write_buf, BMW_WRITE_BUF_SIZE,
        "HTTP/1.1 %d %s\r\n"
        "Server: BareMetalWeb\r\n"
        "Connection: %s\r\n"
        "Content-Length: %zu\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "Referrer-Policy: no-referrer\r\n"
        "Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-eval'\r\n",
        resp->status, status_text(resp->status),
        conn->keep_alive ? "keep-alive" : "close",
        actual_body);

    /* Custom headers */
    for (int i = 0; i < resp->header_count && n < (int)BMW_WRITE_BUF_SIZE - 256; i++) {
        n += snprintf(conn->write_buf + n, BMW_WRITE_BUF_SIZE - n,
                      "%s: %s\r\n", resp->headers[i].name, resp->headers[i].value);
    }

    n += snprintf(conn->write_buf + n, BMW_WRITE_BUF_SIZE - n, "\r\n");

    /* Append body — only the portion we advertised */
    if (resp->body && actual_body > 0) {
        size_t remaining = BMW_WRITE_BUF_SIZE - (size_t)n;
        size_t copy = actual_body < remaining ? actual_body : remaining;
        memcpy(conn->write_buf + n, resp->body, copy);
        n += (int)copy;
    }

    conn->write_len = (size_t)n;
    conn->write_pos = 0;
    conn->state = CONN_WRITING;
    return 0;
}

/* Find connection by fd */
static http_conn_t *find_conn(http_ctx_t *ctx, bmw_socket_t fd) {
    for (int i = 0; i < ctx->conn_count; i++) {
        if (ctx->connections[i].fd == fd) return &ctx->connections[i];
    }
    return NULL;
}

static void close_conn(http_ctx_t *ctx, http_conn_t *conn) {
    bmw_loop_remove_fd(ctx->loop, conn->fd);
    bmw_close_socket(conn->fd);
    conn->state = CONN_CLOSED;
    /* Compact */
    int idx = (int)(conn - ctx->connections);
    if (idx < ctx->conn_count - 1)
        ctx->connections[idx] = ctx->connections[ctx->conn_count - 1];
    ctx->conn_count--;
}

static void http_on_conn_ready(bmw_socket_t fd, int events, void *userdata) {
    http_ctx_t *ctx = (http_ctx_t *)userdata;
    http_conn_t *conn = find_conn(ctx, fd);
    if (!conn) return;

    conn->last_activity = time(NULL);

    if (conn->state == CONN_READING && (events & BMW_EVENT_READ)) {
        int n = recv(fd, conn->read_buf + conn->read_pos,
                     (int)(BMW_READ_BUF_SIZE - conn->read_pos), 0);
        if (n < 0) {
#ifdef _WIN32
            if (WSAGetLastError() == WSAEWOULDBLOCK) return;
#else
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
#endif
            close_conn(ctx, conn);
            return;
        }
        if (n == 0) {
            close_conn(ctx, conn);
            return;
        }
        conn->read_pos += (size_t)n;

        /* Try to parse request */
        bmw_request_t req;
        int parsed = bmw_http_parse_request(conn->read_buf, conn->read_pos, &req);
        if (parsed < 0) {
            /* Bad request */
            bmw_response_t resp;
            bmw_response_init(&resp);
            bmw_response_set_status(&resp, 400);
            bmw_response_set_body(&resp, "Bad Request", 11);
            http_send_response(conn, &resp);
            bmw_response_free(&resp);
            bmw_loop_mod_fd(ctx->loop, fd, BMW_EVENT_WRITE);
            return;
        }
        if (parsed == 0) return; /* incomplete, wait for more data */

        conn->keep_alive = req.keep_alive;

        /* Dispatch to router */
        bmw_response_t resp;
        bmw_response_init(&resp);

        bmw_route_t *route = bmw_router_match(&ctx->router, req.path, req.method);
        if (route) {
            route->handler(&req, &resp, route->userdata);
        } else {
            /* Try static file */
            if (ctx->static_root[0] && req.method == BMW_HTTP_GET) {
                const char *serve_path = req.path;
                /* Map / to /index.html */
                if (strcmp(serve_path, "/") == 0) serve_path = "/index.html";
                bmw_static_serve(ctx->static_root, serve_path, &resp);
            } else {
                bmw_response_set_status(&resp, 404);
                bmw_response_set_body(&resp, "Not Found", 9);
            }
        }

        http_send_response(conn, &resp);
        bmw_response_free(&resp);
        bmw_loop_mod_fd(ctx->loop, fd, BMW_EVENT_WRITE);

        /* Shift remaining data */
        if ((size_t)parsed < conn->read_pos) {
            memmove(conn->read_buf, conn->read_buf + parsed, conn->read_pos - parsed);
            conn->read_pos -= (size_t)parsed;
        } else {
            conn->read_pos = 0;
        }
    }

    if (conn->state == CONN_WRITING && (events & BMW_EVENT_WRITE)) {
        int n = send(fd, conn->write_buf + conn->write_pos,
                     (int)(conn->write_len - conn->write_pos), BMW_SEND_FLAGS);
        if (n < 0) {
#ifdef _WIN32
            if (WSAGetLastError() == WSAEWOULDBLOCK) return;
#else
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
#endif
            close_conn(ctx, conn);
            return;
        }
        if (n == 0) return; /* nothing sent, try again later */
        conn->write_pos += (size_t)n;
        if (conn->write_pos >= conn->write_len) {
            if (conn->keep_alive) {
                conn->state = CONN_READING;
                conn->write_pos = 0;
                conn->write_len = 0;
                bmw_loop_mod_fd(ctx->loop, fd, BMW_EVENT_READ);
            } else {
                close_conn(ctx, conn);
            }
        }
    }
}

static void http_on_accept(bmw_socket_t fd, int events, void *userdata) {
    (void)events;
    http_ctx_t *ctx = (http_ctx_t *)userdata;

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    bmw_socket_t client = accept(fd, (struct sockaddr *)&addr, &addr_len);
    if (client == BMW_INVALID_SOCKET) return;

    if (ctx->conn_count >= BMW_MAX_CONNECTIONS) {
        bmw_close_socket(client);
        return;
    }

    bmw_set_nonblocking(client);

    http_conn_t *conn = &ctx->connections[ctx->conn_count++];
    memset(conn, 0, sizeof(*conn));
    conn->fd = client;
    conn->state = CONN_READING;
    conn->keep_alive = true;
    conn->last_activity = time(NULL);

    bmw_loop_add_fd(ctx->loop, client, BMW_EVENT_READ, http_on_conn_ready, ctx);
}

/* Module interface implementation */
static int http_init(bmw_module_t *self, bmw_config_t *config, bmw_service_registry_t *services) {
    http_ctx_t *ctx = calloc(1, sizeof(http_ctx_t));
    if (!ctx) return -1;
    self->ctx = ctx;
    ctx->port = 8080;
    strcpy(ctx->static_root, "./wwwroot");

    /* Read config */
    if (config) {
        for (int i = 0; i < config->count; i++) {
            if (strcmp(config->entries[i].key, "port") == 0)
                ctx->port = (uint16_t)atoi(config->entries[i].value);
            else if (strcmp(config->entries[i].key, "static_root") == 0) {
                snprintf(ctx->static_root, sizeof(ctx->static_root), "%s", config->entries[i].value);
            }
        }
    }

    /* Resolve static_root to absolute path */
    {
#ifdef _WIN32
        char abs[256];
        if (_fullpath(abs, ctx->static_root, sizeof(abs)))
            snprintf(ctx->static_root, sizeof(ctx->static_root), "%s", abs);
#else
        char *abs = realpath(ctx->static_root, NULL);
        if (abs) { snprintf(ctx->static_root, sizeof(ctx->static_root), "%s", abs); free(abs); }
#endif
    }

    /* Register router as a service so other modules can add routes */
    bmw_registry_register(services, "http.router", &ctx->router);
    return 0;
}

static int http_start(bmw_module_t *self, bmw_event_loop_t *loop) {
    http_ctx_t *ctx = (http_ctx_t *)self->ctx;
    ctx->loop = loop;

    ctx->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (ctx->listen_fd == BMW_INVALID_SOCKET) return -1;

    int opt = 1;
    setsockopt(ctx->listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
    bmw_set_nonblocking(ctx->listen_fd);

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(ctx->port);

    if (bind(ctx->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[HTTP] Failed to bind port %d\n", ctx->port);
        return -1;
    }
    if (listen(ctx->listen_fd, 128) < 0) return -1;

    bmw_loop_add_fd(loop, ctx->listen_fd, BMW_EVENT_READ, http_on_accept, ctx);
    printf("[HTTP] Listening on port %d (static root: %s)\n", ctx->port, ctx->static_root);
    return 0;
}

static void http_stop(bmw_module_t *self) {
    http_ctx_t *ctx = (http_ctx_t *)self->ctx;
    if (!ctx) return;
    /* Close all connections */
    for (int i = 0; i < ctx->conn_count; i++) {
        bmw_close_socket(ctx->connections[i].fd);
    }
    ctx->conn_count = 0;
    if (ctx->listen_fd != BMW_INVALID_SOCKET) {
        bmw_close_socket(ctx->listen_fd);
        ctx->listen_fd = BMW_INVALID_SOCKET;
    }
}

static void http_shutdown(bmw_module_t *self) {
    if (self->ctx) { free(self->ctx); self->ctx = NULL; }
}

/* Slowloris protection: close idle connections (30s timeout) */
#define HTTP_IDLE_TIMEOUT_S 30
static void http_on_tick(bmw_module_t *self) {
    http_ctx_t *ctx = (http_ctx_t *)self->ctx;
    if (!ctx) return;
    time_t now = time(NULL);
    for (int i = ctx->conn_count - 1; i >= 0; i--) {
        if (ctx->connections[i].state != CONN_CLOSED &&
            now - ctx->connections[i].last_activity > HTTP_IDLE_TIMEOUT_S) {
            close_conn(ctx, &ctx->connections[i]);
        }
    }
}

static bmw_module_t http_module = {
    .name = "http",
    .priority = 10,
    .init = http_init,
    .start = http_start,
    .stop = http_stop,
    .shutdown = http_shutdown,
    .on_fd_ready = NULL,
    .handle_request = NULL,
    .on_tick = http_on_tick,
    .ctx = NULL
};

bmw_module_t *bmw_http_module_create(void) {
    return &http_module;
}
