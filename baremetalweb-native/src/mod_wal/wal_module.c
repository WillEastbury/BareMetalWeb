/*
 * WAL Module - wraps WAL engine + optional TCP listener as a pluggable module
 * Registers "wal.engine" service for use by HTTP routes.
 */
#include "bmw_wal.h"
#include "bmw_http.h"
#include "bmw_event_loop.h"

/* Forward declarations from wal_tcp.c */
typedef struct {
    bmw_socket_t listen_fd;
    bmw_event_loop_t *loop;
    wal_engine_t *engine;
    void *clients; /* opaque */
    int client_count;
    uint16_t port;
} wal_tcp_ctx_t;

int  wal_tcp_init(wal_tcp_ctx_t *ctx, wal_engine_t *engine, uint16_t port);
int  wal_tcp_start(wal_tcp_ctx_t *ctx, bmw_event_loop_t *loop);
void wal_tcp_stop(wal_tcp_ctx_t *ctx);

/* WAL module context */
typedef struct {
    wal_engine_t engine;
    wal_tcp_ctx_t tcp;
    uint16_t tcp_port;
    bool tcp_enabled;
} wal_module_ctx_t;

/* HTTP route handler: POST /wal/append  body: key=<key>&value=<value>&op=<op> */
static bmw_result_t wal_http_append(bmw_request_t *req, bmw_response_t *resp, void *userdata) {
    wal_engine_t *engine = (wal_engine_t *)userdata;

    /* Simple key/value extraction from body (url-encoded) */
    if (!req->body || req->body_len == 0) {
        bmw_response_set_status(resp, 400);
        bmw_response_set_body(resp, "{\"error\":\"empty body\"}", 22);
        return BMW_HANDLED;
    }

    /* Parse: expect JSON-like or simple format: key_hash as hex in query */
    uint32_t key_hash = bmw_wal_hash(req->body, req->body_len);
    uint32_t seq = 0;
    int rc = engine->append(engine, key_hash, (const uint8_t *)req->body,
                            (uint16_t)req->body_len, WAL_OP_SET, &seq);
    if (rc == 0) {
        char buf[64];
        int n = snprintf(buf, sizeof(buf), "{\"seq\":%u}", seq);
        bmw_response_set_status(resp, 201);
        bmw_response_add_header(resp, "Content-Type", "application/json");
        bmw_response_set_body(resp, buf, (size_t)n);
    } else {
        bmw_response_set_status(resp, 503);
        bmw_response_set_body(resp, "{\"error\":\"wal full\"}", 20);
    }
    return BMW_HANDLED;
}

/* HTTP route handler: GET /wal/read?key=<key> */
static bmw_result_t wal_http_read(bmw_request_t *req, bmw_response_t *resp, void *userdata) {
    wal_engine_t *engine = (wal_engine_t *)userdata;

    /* Extract key from query string */
    const char *key = req->query;
    if (!key || strlen(key) == 0) {
        bmw_response_set_status(resp, 400);
        bmw_response_set_body(resp, "{\"error\":\"missing key\"}", 23);
        return BMW_HANDLED;
    }

    /* Skip "key=" prefix if present */
    if (strncmp(key, "key=", 4) == 0) key += 4;

    uint32_t key_hash = bmw_wal_hash(key, strlen(key));
    uint8_t buf[WAL_SLOT_SIZE * 4];
    uint32_t delta_count = 0;
    uint16_t total_len = 0;

    int rc = engine->read(engine, key_hash, buf, sizeof(buf), &delta_count, &total_len);
    if (rc == 0) {
        bmw_response_set_status(resp, 200);
        bmw_response_add_header(resp, "Content-Type", "application/octet-stream");
        bmw_response_set_body(resp, (const char *)buf, total_len);
    } else {
        bmw_response_set_status(resp, 404);
        bmw_response_set_body(resp, "{\"error\":\"not found\"}", 21);
    }
    return BMW_HANDLED;
}

/* Module interface */
static int wal_init(bmw_module_t *self, bmw_config_t *config, bmw_service_registry_t *services) {
    wal_module_ctx_t *ctx = calloc(1, sizeof(wal_module_ctx_t));
    if (!ctx) return -1;
    self->ctx = ctx;

    ctx->tcp_port = 8001;
    ctx->tcp_enabled = true;

    if (config) {
        for (int i = 0; i < config->count; i++) {
            if (strcmp(config->entries[i].key, "tcp_port") == 0)
                ctx->tcp_port = (uint16_t)atoi(config->entries[i].value);
            else if (strcmp(config->entries[i].key, "tcp_enabled") == 0)
                ctx->tcp_enabled = (strcmp(config->entries[i].value, "true") == 0);
        }
    }

    wal_engine_init(&ctx->engine);

    /* Register engine as a service */
    bmw_registry_register(services, "wal.engine", &ctx->engine);

    /* Register HTTP routes if router is available */
    bmw_router_t *router = (bmw_router_t *)bmw_registry_get(services, "http.router");
    if (router) {
        bmw_router_add(router, "/wal/append", BMW_HTTP_POST, wal_http_append, &ctx->engine, false);
        bmw_router_add(router, "/wal/read", BMW_HTTP_GET, wal_http_read, &ctx->engine, false);
    }

    return 0;
}

static int wal_start(bmw_module_t *self, bmw_event_loop_t *loop) {
    wal_module_ctx_t *ctx = (wal_module_ctx_t *)self->ctx;

    if (ctx->tcp_enabled) {
        wal_tcp_init(&ctx->tcp, &ctx->engine, ctx->tcp_port);
        return wal_tcp_start(&ctx->tcp, loop);
    }
    return 0;
}

static void wal_stop_fn(bmw_module_t *self) {
    wal_module_ctx_t *ctx = (wal_module_ctx_t *)self->ctx;
    if (ctx && ctx->tcp_enabled) wal_tcp_stop(&ctx->tcp);
}

static void wal_shutdown_fn(bmw_module_t *self) {
    wal_module_ctx_t *ctx = (wal_module_ctx_t *)self->ctx;
    if (ctx) {
        wal_engine_destroy(&ctx->engine);
        free(ctx);
        self->ctx = NULL;
    }
}

static bmw_module_t wal_module = {
    .name = "wal",
    .priority = 20,
    .init = wal_init,
    .start = wal_start,
    .stop = wal_stop_fn,
    .shutdown = wal_shutdown_fn,
    .on_fd_ready = NULL,
    .handle_request = NULL,
    .on_tick = NULL,
    .ctx = NULL
};

bmw_module_t *bmw_wal_module_create(void) {
    return &wal_module;
}
