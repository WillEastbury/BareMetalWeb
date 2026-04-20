/*
 * WAL TCP protocol adapter - PicoWAL wire protocol on configurable port
 * Protocol:
 *   APPEND: [0x01][key_hash:4 LE][value_len:2 LE][op:1][value...]
 *   READ:   [0x02][key_hash:4 LE]
 *   NOOP:   [0x00]
 *   Ack APPEND: [0x81][seq:4 LE]
 *   Ack READ:   [0x82][delta_count:4 LE][total_len:2 LE][data...]
 *   Ack NOOP:   [0x80]
 *   Error:       [0xFF][error_code:1]
 */
#include "bmw_wal.h"
#include "bmw_event_loop.h"

#ifndef _WIN32
#include <errno.h>
#endif

/* Helper: send all bytes, tolerating EWOULDBLOCK by retrying. Returns 0 on success. */
static int wal_tcp_send_all(bmw_socket_t fd, const char *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(fd, buf + sent, len - sent, 0);
        if (n > 0) { sent += n; continue; }
        if (n < 0) {
#ifdef _WIN32
            if (WSAGetLastError() == WSAEWOULDBLOCK) continue;
#else
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
#endif
        }
        return -1; /* real error */
    }
    return 0;
}

#define WAL_TCP_MAX_CLIENTS 4
#define WAL_TCP_BUF_SIZE    512

typedef struct {
    bmw_socket_t fd;
    uint8_t buf[WAL_TCP_BUF_SIZE];
    size_t buf_pos;
    bool active;
    time_t last_activity;
} wal_tcp_client_t;

typedef struct {
    bmw_socket_t listen_fd;
    bmw_event_loop_t *loop;
    wal_engine_t *engine;
    wal_tcp_client_t clients[WAL_TCP_MAX_CLIENTS];
    int client_count;
    uint16_t port;
} wal_tcp_ctx_t;

static wal_tcp_client_t *wal_tcp_find_client(wal_tcp_ctx_t *ctx, bmw_socket_t fd) {
    for (int i = 0; i < ctx->client_count; i++) {
        if (ctx->clients[i].fd == fd && ctx->clients[i].active)
            return &ctx->clients[i];
    }
    return NULL;
}

static void wal_tcp_close_client(wal_tcp_ctx_t *ctx, wal_tcp_client_t *client) {
    bmw_loop_remove_fd(ctx->loop, client->fd);
    bmw_close_socket(client->fd);
    client->active = false;
    /* Compact */
    int idx = (int)(client - ctx->clients);
    if (idx < ctx->client_count - 1)
        ctx->clients[idx] = ctx->clients[ctx->client_count - 1];
    ctx->client_count--;
}

static void wal_tcp_send_error(bmw_socket_t fd, uint8_t code) {
    uint8_t resp[2] = { WAL_TCP_ACK_ERROR, code };
    wal_tcp_send_all(fd, (const char *)resp, 2);
}

static void wal_tcp_process(wal_tcp_ctx_t *ctx, wal_tcp_client_t *client) {
    while (client->buf_pos > 0) {
        uint8_t opcode = client->buf[0];

        if (opcode == WAL_TCP_OP_NOOP) {
            uint8_t ack = WAL_TCP_ACK_NOOP;
            wal_tcp_send_all(client->fd, (const char *)&ack, 1);
            memmove(client->buf, client->buf + 1, --client->buf_pos);
            continue;
        }

        if (opcode == WAL_TCP_OP_APPEND) {
            /* Need: 1 + 4 + 2 + 1 = 8 bytes header minimum */
            if (client->buf_pos < 8) return; /* wait for more */

            uint32_t key_hash;
            uint16_t value_len;
            uint8_t op;
            memcpy(&key_hash, client->buf + 1, 4);
            memcpy(&value_len, client->buf + 5, 2);
            op = client->buf[7];

            size_t total_needed = 8 + value_len;
            if (client->buf_pos < total_needed) return; /* wait for more */

            uint32_t seq = 0;
            int rc = ctx->engine->append(ctx->engine, key_hash,
                                         client->buf + 8, value_len, (wal_op_t)op, &seq);
            if (rc == 0) {
                uint8_t ack[5];
                ack[0] = WAL_TCP_ACK_APPEND;
                memcpy(ack + 1, &seq, 4);
                wal_tcp_send_all(client->fd, (const char *)ack, 5);
            } else if (rc == -1) {
                wal_tcp_send_error(client->fd, WAL_TCP_ERR_FULL);
            } else {
                wal_tcp_send_error(client->fd, WAL_TCP_ERR_TOOBIG);
            }

            memmove(client->buf, client->buf + total_needed, client->buf_pos - total_needed);
            client->buf_pos -= total_needed;
            continue;
        }

        if (opcode == WAL_TCP_OP_READ) {
            if (client->buf_pos < 5) return; /* need 1 + 4 */

            uint32_t key_hash;
            memcpy(&key_hash, client->buf + 1, 4);

            uint8_t result_buf[WAL_SLOT_SIZE * 4];
            uint32_t delta_count = 0;
            uint16_t total_len = 0;

            int rc = ctx->engine->read(ctx->engine, key_hash, result_buf,
                                       sizeof(result_buf), &delta_count, &total_len);
            if (rc == 0) {
                uint8_t hdr[7];
                hdr[0] = WAL_TCP_ACK_READ;
                memcpy(hdr + 1, &delta_count, 4);
                memcpy(hdr + 5, &total_len, 2);
                wal_tcp_send_all(client->fd, (const char *)hdr, 7);
                if (total_len > 0)
                    wal_tcp_send_all(client->fd, (const char *)result_buf, total_len);
            } else {
                /* Not found: return 0 deltas */
                uint8_t hdr[7] = { WAL_TCP_ACK_READ, 0,0,0,0, 0,0 };
                wal_tcp_send_all(client->fd, (const char *)hdr, 7);
            }

            memmove(client->buf, client->buf + 5, client->buf_pos - 5);
            client->buf_pos -= 5;
            continue;
        }

        /* Unknown opcode */
        wal_tcp_send_error(client->fd, WAL_TCP_ERR_PROTO);
        wal_tcp_close_client(ctx, client);
        return;
    }
}

static void wal_tcp_on_client(bmw_socket_t fd, int events, void *userdata) {
    wal_tcp_ctx_t *ctx = (wal_tcp_ctx_t *)userdata;
    if (!(events & BMW_EVENT_READ)) return;

    wal_tcp_client_t *client = wal_tcp_find_client(ctx, fd);
    if (!client) return;

    int n = recv(fd, (char *)(client->buf + client->buf_pos),
                 (int)(WAL_TCP_BUF_SIZE - client->buf_pos), 0);
    if (n < 0) {
#ifdef _WIN32
        if (WSAGetLastError() == WSAEWOULDBLOCK) return;
#else
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
#endif
        wal_tcp_close_client(ctx, client);
        return;
    }
    if (n == 0) {
        wal_tcp_close_client(ctx, client);
        return;
    }
    client->buf_pos += (size_t)n;
    client->last_activity = time(NULL);
    wal_tcp_process(ctx, client);
}

static void wal_tcp_on_accept(bmw_socket_t fd, int events, void *userdata) {
    (void)events;
    wal_tcp_ctx_t *ctx = (wal_tcp_ctx_t *)userdata;

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    bmw_socket_t client_fd = accept(fd, (struct sockaddr *)&addr, &addr_len);
    if (client_fd == BMW_INVALID_SOCKET) return;

    if (ctx->client_count >= WAL_TCP_MAX_CLIENTS) {
        bmw_close_socket(client_fd);
        return;
    }

    bmw_set_nonblocking(client_fd);

    wal_tcp_client_t *client = &ctx->clients[ctx->client_count++];
    memset(client, 0, sizeof(*client));
    client->fd = client_fd;
    client->active = true;
    client->last_activity = time(NULL);

    bmw_loop_add_fd(ctx->loop, client_fd, BMW_EVENT_READ, wal_tcp_on_client, ctx);
}

/* Public: initialize the WAL TCP adapter */
int wal_tcp_init(wal_tcp_ctx_t *ctx, wal_engine_t *engine, uint16_t port) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->engine = engine;
    ctx->port = port;
    ctx->listen_fd = BMW_INVALID_SOCKET;
    return 0;
}

int wal_tcp_start(wal_tcp_ctx_t *ctx, bmw_event_loop_t *loop) {
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
        fprintf(stderr, "[WAL-TCP] Failed to bind port %d\n", ctx->port);
        return -1;
    }
    if (listen(ctx->listen_fd, 16) < 0) return -1;

    bmw_loop_add_fd(loop, ctx->listen_fd, BMW_EVENT_READ, wal_tcp_on_accept, ctx);
    printf("[WAL-TCP] Listening on port %d\n", ctx->port);
    return 0;
}

/* Evict idle WAL TCP clients (30s timeout) */
#define WAL_TCP_IDLE_TIMEOUT_S 30
void wal_tcp_tick(wal_tcp_ctx_t *ctx) {
    time_t now = time(NULL);
    for (int i = ctx->client_count - 1; i >= 0; i--) {
        if (ctx->clients[i].active &&
            now - ctx->clients[i].last_activity > WAL_TCP_IDLE_TIMEOUT_S) {
            wal_tcp_close_client(ctx, &ctx->clients[i]);
        }
    }
}

void wal_tcp_stop(wal_tcp_ctx_t *ctx) {
    for (int i = 0; i < ctx->client_count; i++) {
        if (ctx->clients[i].active)
            bmw_close_socket(ctx->clients[i].fd);
    }
    ctx->client_count = 0;
    if (ctx->listen_fd != BMW_INVALID_SOCKET) {
        bmw_close_socket(ctx->listen_fd);
        ctx->listen_fd = BMW_INVALID_SOCKET;
    }
}
