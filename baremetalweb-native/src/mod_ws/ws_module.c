/*
 * WebSocket Module - RFC 6455 upgrade + BMW binary frame protocol
 * Handles /bmw/ws endpoint for real-time entity operations.
 */
#include "bmw_ws.h"
#include "bmw_http.h"
#include "bmw_meta.h"
#include "bmw_auth.h"

#ifdef _WIN32
#define strncasecmp _strnicmp
#endif

/* Minimal Base64 encoder for WebSocket accept key */
static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_encode(const uint8_t *in, size_t len, char *out) {
    size_t i = 0, j = 0;
    while (i < len) {
        uint32_t a = i < len ? in[i++] : 0;
        uint32_t b = i < len ? in[i++] : 0;
        uint32_t c = i < len ? in[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;
        out[j++] = b64[(triple >> 18) & 0x3F];
        out[j++] = b64[(triple >> 12) & 0x3F];
        out[j++] = (i > len + 1) ? '=' : b64[(triple >> 6) & 0x3F];
        out[j++] = (i > len) ? '=' : b64[triple & 0x3F];
    }
    out[j] = '\0';
}

/* SHA-1 for WebSocket accept (RFC 6455 requires it) */
static void sha1(const uint8_t *data, size_t len, uint8_t out[20]) {
    uint32_t h0=0x67452301, h1=0xEFCDAB89, h2=0x98BADCFE, h3=0x10325476, h4=0xC3D2E1F0;
    size_t new_len = len + 1;
    while (new_len % 64 != 56) new_len++;
    uint8_t *msg = calloc(new_len + 8, 1);
    memcpy(msg, data, len);
    msg[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) msg[new_len + 7 - i] = (uint8_t)(bits >> (i*8));

    for (size_t chunk = 0; chunk < new_len + 8; chunk += 64) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)msg[chunk+i*4]<<24)|((uint32_t)msg[chunk+i*4+1]<<16)|
                   ((uint32_t)msg[chunk+i*4+2]<<8)|msg[chunk+i*4+3];
        for (int i = 16; i < 80; i++) {
            uint32_t t = w[i-3]^w[i-8]^w[i-14]^w[i-16];
            w[i] = (t<<1)|(t>>31);
        }
        uint32_t a=h0,b_=h1,c=h2,d=h3,e=h4;
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i<20)      { f=(b_&c)|((~b_)&d); k=0x5A827999; }
            else if (i<40) { f=b_^c^d; k=0x6ED9EBA1; }
            else if (i<60) { f=(b_&c)|(b_&d)|(c&d); k=0x8F1BBCDC; }
            else           { f=b_^c^d; k=0xCA62C1D6; }
            uint32_t temp = ((a<<5)|(a>>27)) + f + e + k + w[i];
            e=d; d=c; c=(b_<<30)|(b_>>2); b_=a; a=temp;
        }
        h0+=a; h1+=b_; h2+=c; h3+=d; h4+=e;
    }
    free(msg);
    uint32_t hh[5] = {h0,h1,h2,h3,h4};
    for (int i = 0; i < 5; i++) {
        out[i*4]   = (uint8_t)(hh[i]>>24);
        out[i*4+1] = (uint8_t)(hh[i]>>16);
        out[i*4+2] = (uint8_t)(hh[i]>>8);
        out[i*4+3] = (uint8_t)(hh[i]);
    }
}

/* WebSocket client state */
typedef struct {
    bmw_socket_t fd;
    bool active;
    bool upgraded;
    uint8_t buf[BMW_WS_BUF_SIZE];
    size_t buf_pos;
} ws_client_t;

typedef struct {
    ws_client_t clients[BMW_WS_MAX_CLIENTS];
    int client_count;
    bmw_event_loop_t *loop;
    bmw_meta_ctx_t *meta;
} ws_ctx_t;

/* Send a WebSocket frame */
static void ws_send_frame(bmw_socket_t fd, uint8_t opcode, const uint8_t *data, size_t len) {
    uint8_t frame[BMW_WS_BUF_SIZE];
    size_t pos = 0;
    frame[pos++] = 0x80 | opcode; /* FIN + opcode */
    if (len < 126) {
        frame[pos++] = (uint8_t)len;
    } else {
        frame[pos++] = 126;
        frame[pos++] = (uint8_t)(len >> 8);
        frame[pos++] = (uint8_t)(len & 0xFF);
    }
    if (pos + len <= sizeof(frame)) {
        memcpy(frame + pos, data, len);
        send(fd, (const char *)frame, (int)(pos + len), 0);
    }
}

/* Process a BMW binary frame from a WebSocket message */
static void ws_process_bmw_frame(ws_ctx_t *ctx, ws_client_t *client,
                                 const uint8_t *data, size_t len) {
    if (len < BMW_WS_FRAME_HDR_SIZE) return;

    uint16_t opcode_shifted;
    uint32_t entity_id;
    memcpy(&opcode_shifted, data, 2);
    memcpy(&entity_id, data + 2, 4);
    uint8_t opcode = (uint8_t)(opcode_shifted >> 2);

    /* Response buffer */
    uint8_t resp[BMW_WS_BUF_SIZE];
    size_t resp_len = 0;

    switch (opcode) {
    case BMW_WS_OP_SCHEMA_REQ: {
        /* Return entity schema as binary frame */
        if (!ctx->meta || (int)entity_id >= ctx->meta->entity_count) break;
        bmw_entity_def_t *ent = &ctx->meta->entities[entity_id];
        /* Pack response header */
        uint16_t resp_op = BMW_WS_OP_SCHEMA_RESP << 2;
        memcpy(resp, &resp_op, 2);
        memcpy(resp + 2, &entity_id, 4);
        /* Minimal JSON schema as payload */
        int n = snprintf((char *)resp + 9, sizeof(resp) - 9,
            "{\"name\":\"%s\",\"fields\":%d}", ent->name, ent->field_count);
        /* 3-byte JSON length */
        resp[6] = (uint8_t)(n & 0xFF);
        resp[7] = (uint8_t)((n >> 8) & 0xFF);
        resp[8] = 0;
        resp_len = 9 + n;
        break;
    }
    case BMW_WS_OP_LIST_REQ: {
        if (!ctx->meta || (int)entity_id >= ctx->meta->entity_count) break;
        uint16_t resp_op = BMW_WS_OP_LIST_RESP << 2;
        memcpy(resp, &resp_op, 2);
        memcpy(resp + 2, &entity_id, 4);
        int n = snprintf((char *)resp + 9, sizeof(resp) - 9, "{\"count\":%d}",
                         ctx->meta->record_counts[entity_id]);
        resp[6] = (uint8_t)(n & 0xFF);
        resp[7] = (uint8_t)((n >> 8) & 0xFF);
        resp[8] = 0;
        resp_len = 9 + n;
        break;
    }
    default: {
        /* Error response */
        uint16_t resp_op = BMW_WS_OP_ERROR << 2;
        memcpy(resp, &resp_op, 2);
        memcpy(resp + 2, &entity_id, 4);
        resp_len = 6;
        break;
    }
    }

    if (resp_len > 0)
        ws_send_frame(client->fd, WS_OP_BINARY, resp, resp_len);
}

/* Process incoming WebSocket data */
static void ws_on_data(ws_ctx_t *ctx, ws_client_t *client) {
    while (client->buf_pos >= 2) {
        uint8_t b0 = client->buf[0];
        uint8_t b1 = client->buf[1];
        bool masked = (b1 & 0x80) != 0;
        size_t payload_len = b1 & 0x7F;
        size_t hdr_len = 2;

        if (payload_len == 126) {
            if (client->buf_pos < 4) return;
            payload_len = ((size_t)client->buf[2] << 8) | client->buf[3];
            hdr_len = 4;
        } else if (payload_len == 127) {
            return; /* too large for Pico */
        }

        size_t mask_len = masked ? 4 : 0;
        size_t frame_len = hdr_len + mask_len + payload_len;
        if (client->buf_pos < frame_len) return;

        uint8_t *mask_key = client->buf + hdr_len;
        uint8_t *payload = client->buf + hdr_len + mask_len;

        /* Unmask */
        if (masked) {
            for (size_t i = 0; i < payload_len; i++)
                payload[i] ^= mask_key[i % 4];
        }

        uint8_t op = b0 & 0x0F;
        if (op == WS_OP_CLOSE) {
            ws_send_frame(client->fd, WS_OP_CLOSE, NULL, 0);
            client->active = false;
            return;
        } else if (op == WS_OP_PING) {
            ws_send_frame(client->fd, WS_OP_PONG, payload, payload_len);
        } else if (op == WS_OP_BINARY) {
            ws_process_bmw_frame(ctx, client, payload, payload_len);
        }

        /* Shift buffer */
        memmove(client->buf, client->buf + frame_len, client->buf_pos - frame_len);
        client->buf_pos -= frame_len;
    }
}

/* HTTP handler for WebSocket upgrade at /bmw/ws */
static bmw_result_t ws_upgrade_handler(bmw_request_t *req, bmw_response_t *resp, void *ud) {
    ws_ctx_t *ctx = (ws_ctx_t *)ud;

    /* Validate RFC 6455 required headers */
    const char *ws_key = NULL;
    bool has_upgrade = false, has_connection = false;
    for (int i = 0; i < req->header_count; i++) {
        if (strncasecmp(req->headers[i].name, "Upgrade", 7) == 0 &&
            strncasecmp(req->headers[i].value, "websocket", 9) == 0)
            has_upgrade = true;
        if (strncasecmp(req->headers[i].name, "Connection", 10) == 0 &&
            strstr(req->headers[i].value, "Upgrade"))
            has_connection = true;
        if (strncasecmp(req->headers[i].name, "Sec-WebSocket-Key", 17) == 0)
            ws_key = req->headers[i].value;
    }

    if (!has_upgrade || !has_connection || !ws_key) {
        bmw_response_set_status(resp, 400);
        bmw_response_set_body(resp, "{\"error\":\"missing WebSocket upgrade headers\"}", 45);
        return BMW_HANDLED;
    }

    /* Compute Sec-WebSocket-Accept per RFC 6455 */
    static const char ws_magic[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char concat[128];
    int clen = snprintf(concat, sizeof(concat), "%s%s", ws_key, ws_magic);
    uint8_t hash[20];
    sha1((const uint8_t *)concat, (size_t)clen, hash);
    char accept_b64[32];
    base64_encode(hash, 20, accept_b64);

    bmw_response_set_status(resp, 101);
    bmw_response_add_header(resp, "Upgrade", "websocket");
    bmw_response_add_header(resp, "Connection", "Upgrade");
    bmw_response_add_header(resp, "Sec-WebSocket-Accept", accept_b64);

    /* NOTE: Full raw-socket handoff for WS framing still requires event loop integration.
     * The proper Sec-WebSocket-Accept is now sent so clients can complete the handshake. */
    (void)ctx;
    return BMW_HANDLED;
}

/* Module interface */
static int ws_init(bmw_module_t *self, bmw_config_t *config, bmw_service_registry_t *services) {
    (void)config;
    ws_ctx_t *ctx = calloc(1, sizeof(ws_ctx_t));
    if (!ctx) return -1;
    self->ctx = ctx;

    ctx->meta = (bmw_meta_ctx_t *)bmw_registry_get(services, "meta.ctx");

    bmw_router_t *router = (bmw_router_t *)bmw_registry_get(services, "http.router");
    if (router) {
        bmw_router_add(router, "/bmw/ws", BMW_HTTP_GET, ws_upgrade_handler, ctx, false);
    }

    bmw_registry_register(services, "ws.ctx", ctx);
    return 0;
}

static void ws_shutdown_fn(bmw_module_t *self) {
    if (self->ctx) { free(self->ctx); self->ctx = NULL; }
}

static bmw_module_t ws_module = {
    .name = "websocket",
    .priority = 25,
    .init = ws_init,
    .start = NULL,
    .stop = NULL,
    .shutdown = ws_shutdown_fn,
    .on_fd_ready = NULL,
    .handle_request = NULL,
    .on_tick = NULL,
    .ctx = NULL
};

bmw_module_t *bmw_ws_module_create(void) {
    return &ws_module;
}
