/* bmw_pico_lwip.c — lwIP raw-API HTTP server for BareMetalWeb on Pico 2W
 *
 * Single-threaded, callback-driven. Runs on Core 0 alongside cyw43_arch polling.
 * All static content served from flash-embedded arrays (zero-copy where possible).
 */
#include "bmw_pico_lwip.h"
#include <stdlib.h>

/* ---- Minimal HTTP parser (inline, request-only) ---- */
static int pico_parse_request(const uint8_t *buf, uint16_t len, bmw_pico_request_t *req) {
    memset(req, 0, sizeof(*req));
    req->keep_alive = true;

    const char *s = (const char *)buf;
    const char *end = s + len;

    /* Find end of request line */
    const char *eol = memchr(s, '\r', len);
    if (!eol || eol + 1 >= end || eol[1] != '\n') return -1;

    /* Method */
    const char *sp = memchr(s, ' ', eol - s);
    if (!sp) return -1;
    size_t mlen = sp - s;
    if (mlen >= sizeof(req->method)) mlen = sizeof(req->method) - 1;
    memcpy(req->method, s, mlen);
    req->method[mlen] = '\0';
    s = sp + 1;

    /* Path + query */
    sp = memchr(s, ' ', eol - s);
    if (!sp) return -1;
    const char *qmark = memchr(s, '?', sp - s);
    if (qmark) {
        size_t plen = qmark - s;
        if (plen >= sizeof(req->path)) plen = sizeof(req->path) - 1;
        memcpy(req->path, s, plen);
        req->path[plen] = '\0';
        size_t qlen = sp - qmark - 1;
        if (qlen >= sizeof(req->query)) qlen = sizeof(req->query) - 1;
        memcpy(req->query, qmark + 1, qlen);
        req->query[qlen] = '\0';
    } else {
        size_t plen = sp - s;
        if (plen >= sizeof(req->path)) plen = sizeof(req->path) - 1;
        memcpy(req->path, s, plen);
        req->path[plen] = '\0';
    }

    s = eol + 2; /* skip \r\n */

    /* Headers */
    while (s + 1 < end && !(s[0] == '\r' && s[1] == '\n')) {
        eol = memchr(s, '\r', end - s);
        if (!eol || eol + 1 >= end) break;
        const char *colon = memchr(s, ':', eol - s);
        if (colon && req->header_count < BMW_PICO_MAX_HEADERS) {
            bmw_pico_header_t *h = &req->headers[req->header_count];
            size_t nlen = colon - s;
            if (nlen >= sizeof(h->name)) nlen = sizeof(h->name) - 1;
            memcpy(h->name, s, nlen);
            h->name[nlen] = '\0';
            const char *val = colon + 1;
            while (val < eol && *val == ' ') val++;
            size_t vlen = eol - val;
            if (vlen >= sizeof(h->value)) vlen = sizeof(h->value) - 1;
            memcpy(h->value, val, vlen);
            h->value[vlen] = '\0';
            req->header_count++;

            /* Check Connection: close */
            if (nlen == 10 && strncasecmp(h->name, "Connection", 10) == 0) {
                if (strncasecmp(h->value, "close", 5) == 0) req->keep_alive = false;
            }
        }
        s = eol + 2;
    }

    if (s + 1 < end && s[0] == '\r' && s[1] == '\n') {
        s += 2;
        if (s < end) {
            req->body = s;
            req->body_len = end - s;
        }
    }

    return (int)(s - (const char *)buf);
}

/* ---- Status text ---- */
static const char *status_text(int code) {
    switch (code) {
        case 200: return "OK";
        case 301: return "Moved Permanently";
        case 304: return "Not Modified";
        case 400: return "Bad Request";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 500: return "Internal Server Error";
        default:  return "OK";
    }
}

/* ---- Response helpers ---- */
void bmw_pico_resp_set_body(bmw_pico_response_t *resp, const uint8_t *data, size_t len, bool is_static) {
    resp->body = data;
    resp->body_len = len;
    resp->body_is_static = is_static;
}

void bmw_pico_resp_add_header(bmw_pico_response_t *resp, const char *name, const char *value) {
    if (resp->header_count >= 8) return;
    bmw_pico_header_t *h = &resp->headers[resp->header_count++];
    snprintf(h->name, sizeof(h->name), "%s", name);
    snprintf(h->value, sizeof(h->value), "%s", value);
}

/* ---- Embedded static file handler ---- */
int bmw_pico_static_handler(bmw_pico_request_t *req, bmw_pico_response_t *resp, void *ctx) {
    (void)ctx;
    for (size_t i = 0; i < bmw_embedded_file_count; i++) {
        if (strcmp(req->path, bmw_embedded_files[i].path) == 0) {
            resp->status = 200;
            bmw_pico_resp_add_header(resp, "Content-Type", bmw_embedded_files[i].mime);
            bmw_pico_resp_set_body(resp, bmw_embedded_files[i].data, bmw_embedded_files[i].len, true);
            return 1;
        }
    }
    return 0; /* not handled */
}

/* ---- Send response via lwIP ---- */
static void pico_send_response(struct tcp_pcb *pcb, bmw_pico_conn_t *conn,
                               bmw_pico_response_t *resp) {
    char hdr[512];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Server: BareMetalWeb-Pico/1.0\r\n"
        "Connection: %s\r\n"
        "Content-Length: %zu\r\n",
        resp->status, status_text(resp->status),
        conn->keep_alive ? "keep-alive" : "close",
        resp->body_len);

    for (int i = 0; i < resp->header_count && n < (int)sizeof(hdr) - 128; i++) {
        n += snprintf(hdr + n, sizeof(hdr) - n, "%s: %s\r\n",
                      resp->headers[i].name, resp->headers[i].value);
    }
    n += snprintf(hdr + n, sizeof(hdr) - n, "\r\n");

    /* Send headers (always copy — stack buffer) */
    tcp_write(pcb, hdr, (uint16_t)n, TCP_WRITE_FLAG_COPY);
    conn->bytes_in_flight += (uint16_t)n;

    /* Send body — zero-copy for static (flash) data */
    if (resp->body && resp->body_len > 0) {
        uint8_t flags = resp->body_is_static ? 0 : TCP_WRITE_FLAG_COPY;
        size_t sent = 0;
        while (sent < resp->body_len) {
            uint16_t sndbuf = tcp_sndbuf(pcb);
            if (sndbuf == 0) break;
            size_t chunk = resp->body_len - sent;
            if (chunk > sndbuf) chunk = sndbuf;
            if (chunk > 0xFFFF) chunk = 0xFFFF;
            err_t err = tcp_write(pcb, resp->body + sent, (uint16_t)chunk, flags);
            if (err != ERR_OK) break;
            sent += chunk;
            conn->bytes_in_flight += (uint16_t)chunk;
        }
        /* Track unsent remainder for resume in sent callback */
        if (sent < resp->body_len) {
            conn->pending_body = resp->body;
            conn->pending_body_len = resp->body_len;
            conn->pending_body_sent = sent;
            conn->pending_is_static = resp->body_is_static;
            conn->state = PCONN_WRITING;
        }
    }
    tcp_output(pcb);
}

/* ---- Connection management ---- */
static bmw_pico_conn_t *conn_alloc(bmw_pico_server_t *srv) {
    for (int i = 0; i < BMW_PICO_MAX_CONN; i++) {
        if (!srv->conns[i].in_use) {
            memset(&srv->conns[i], 0, sizeof(bmw_pico_conn_t));
            srv->conns[i].in_use = true;
            srv->conns[i].state = PCONN_READING;
            return &srv->conns[i];
        }
    }
    return NULL;
}

static void conn_close(struct tcp_pcb *pcb, bmw_pico_conn_t *conn) {
    if (pcb) {
        tcp_arg(pcb, NULL);
        tcp_recv(pcb, NULL);
        tcp_err(pcb, NULL);
        tcp_sent(pcb, NULL);
        tcp_poll(pcb, NULL, 0);
        if (tcp_close(pcb) != ERR_OK) tcp_abort(pcb);
    }
    if (conn) {
        if (conn->dyn_body) { free(conn->dyn_body); conn->dyn_body = NULL; }
        conn->in_use = false;
        conn->pcb = NULL;
    }
}

/* ---- Dispatch request through routes ---- */
static void dispatch_request(bmw_pico_server_t *srv, struct tcp_pcb *pcb,
                             bmw_pico_conn_t *conn, bmw_pico_request_t *req) {
    bmw_pico_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.status = 404;

    /* Try routes in order */
    for (int i = 0; i < srv->route_count; i++) {
        bmw_pico_route_t *r = &srv->routes[i];
        bool match = r->exact
            ? (strcmp(req->path, r->prefix) == 0)
            : (strncmp(req->path, r->prefix, strlen(r->prefix)) == 0);
        if (match) {
            int handled = r->handler(req, &resp, r->ctx);
            if (handled) break;
        }
    }

    if (resp.status == 404 && resp.body == NULL) {
        static const char msg404[] = "Not Found";
        bmw_pico_resp_add_header(&resp, "Content-Type", "text/plain");
        bmw_pico_resp_set_body(&resp, (const uint8_t *)msg404, 9, true);
    }

    pico_send_response(pcb, conn, &resp);

    /* Free dynamic body if any — tcp_write was called with COPY flag */
    if (!resp.body_is_static && resp.body) {
        free((void *)resp.body);
    }
}

/* ---- lwIP callbacks ---- */
static err_t pico_recv_cb(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    bmw_pico_conn_t *conn = (bmw_pico_conn_t *)arg;
    if (!conn) { if (p) pbuf_free(p); return ERR_OK; }

    bmw_pico_server_t *srv = (bmw_pico_server_t *)conn->dyn_body; /* stashed in accept */
    /* Actually we need a better way to get srv — use a global */

    if (!p || err != ERR_OK) {
        conn_close(pcb, conn);
        return ERR_OK;
    }

    /* Copy pbuf into read buffer */
    uint16_t copy = p->tot_len;
    if (conn->read_pos + copy > BMW_PICO_READ_BUF) copy = BMW_PICO_READ_BUF - conn->read_pos;
    pbuf_copy_partial(p, conn->read_buf + conn->read_pos, copy, 0);
    conn->read_pos += copy;
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);

    /* Check for complete HTTP request (\r\n\r\n) */
    const char *hdr_end = NULL;
    uint16_t hdr_end_offset = 0;
    for (uint16_t i = 0; i + 3 < conn->read_pos; i++) {
        if (conn->read_buf[i] == '\r' && conn->read_buf[i+1] == '\n' &&
            conn->read_buf[i+2] == '\r' && conn->read_buf[i+3] == '\n') {
            hdr_end = (const char *)&conn->read_buf[i+4];
            hdr_end_offset = i + 4;
            break;
        }
    }
    if (!hdr_end) return ERR_OK; /* wait for more data */

    /* Parse Content-Length from headers to wait for full body */
    uint32_t content_length = 0;
    {
        const char *cl = NULL;
        for (uint16_t i = 0; i + 15 < hdr_end_offset; i++) {
            if (strncasecmp((const char *)&conn->read_buf[i], "Content-Length:", 15) == 0) {
                cl = (const char *)&conn->read_buf[i + 15];
                while (*cl == ' ') cl++;
                content_length = (uint32_t)strtoul(cl, NULL, 10);
                break;
            }
        }
        /* Cap content length to prevent buffer overflow */
        if (content_length > BMW_PICO_READ_BUF - hdr_end_offset)
            content_length = BMW_PICO_READ_BUF - hdr_end_offset;
        /* Wait for full body if not yet received */
        if (conn->read_pos < hdr_end_offset + content_length)
            return ERR_OK;
    }

    bmw_pico_request_t req;
    int parsed = pico_parse_request(conn->read_buf, conn->read_pos, &req);
    if (parsed < 0) {
        conn_close(pcb, conn);
        return ERR_OK;
    }

    conn->keep_alive = req.keep_alive;

    /* We need srv pointer — use global */
    extern bmw_pico_server_t g_bmw_server;
    dispatch_request(&g_bmw_server, pcb, conn, &req);

    /* Reset for keep-alive */
    if (conn->keep_alive) {
        conn->read_pos = 0;
    } else {
        conn_close(pcb, conn);
    }

    return ERR_OK;
}

static void pico_err_cb(void *arg, err_t err) {
    bmw_pico_conn_t *conn = (bmw_pico_conn_t *)arg;
    (void)err;
    if (conn) { conn->in_use = false; conn->pcb = NULL; }
}

static err_t pico_sent_cb(void *arg, struct tcp_pcb *pcb, u16_t len) {
    bmw_pico_conn_t *conn = (bmw_pico_conn_t *)arg;
    if (!conn) return ERR_OK;
    if (conn->bytes_in_flight > len) conn->bytes_in_flight -= len;
    else conn->bytes_in_flight = 0;

    /* Resume sending pending body data */
    if (conn->pending_body && conn->pending_body_sent < conn->pending_body_len) {
        uint8_t flags = conn->pending_is_static ? 0 : TCP_WRITE_FLAG_COPY;
        while (conn->pending_body_sent < conn->pending_body_len) {
            uint16_t sndbuf = tcp_sndbuf(pcb);
            if (sndbuf == 0) break;
            size_t chunk = conn->pending_body_len - conn->pending_body_sent;
            if (chunk > sndbuf) chunk = sndbuf;
            if (chunk > 0xFFFF) chunk = 0xFFFF;
            err_t err = tcp_write(pcb, conn->pending_body + conn->pending_body_sent,
                                  (uint16_t)chunk, flags);
            if (err != ERR_OK) break;
            conn->pending_body_sent += chunk;
            conn->bytes_in_flight += (uint16_t)chunk;
        }
        if (conn->pending_body_sent >= conn->pending_body_len) {
            /* Done sending — free dynamic body if needed */
            if (!conn->pending_is_static && conn->pending_body) {
                free((void *)conn->pending_body);
            }
            conn->pending_body = NULL;
            conn->pending_body_len = 0;
            conn->pending_body_sent = 0;
            conn->state = PCONN_READING;
        }
        tcp_output(pcb);
    }
    return ERR_OK;
}

static err_t pico_poll_cb(void *arg, struct tcp_pcb *pcb) {
    bmw_pico_conn_t *conn = (bmw_pico_conn_t *)arg;
    if (!conn || !conn->in_use) { conn_close(pcb, conn); }
    return ERR_OK;
}

static err_t pico_accept_cb(void *arg, struct tcp_pcb *newpcb, err_t err) {
    bmw_pico_server_t *srv = (bmw_pico_server_t *)arg;
    if (err != ERR_OK || !newpcb) return ERR_VAL;

    bmw_pico_conn_t *conn = conn_alloc(srv);
    if (!conn) { tcp_abort(newpcb); return ERR_ABRT; }

    conn->pcb = newpcb;
    tcp_arg(newpcb, conn);
    tcp_recv(newpcb, pico_recv_cb);
    tcp_err(newpcb, pico_err_cb);
    tcp_sent(newpcb, pico_sent_cb);
    tcp_poll(newpcb, pico_poll_cb, 20); /* ~10s idle timeout */

    return ERR_OK;
}

/* ---- Public API ---- */
void bmw_pico_server_init(bmw_pico_server_t *srv) {
    memset(srv, 0, sizeof(*srv));
}

bool bmw_pico_server_start(bmw_pico_server_t *srv, uint16_t port) {
    struct tcp_pcb *pcb = tcp_new();
    if (!pcb) return false;

    if (tcp_bind(pcb, IP_ADDR_ANY, port) != ERR_OK) {
        tcp_close(pcb);
        return false;
    }

    srv->listen_pcb = tcp_listen(pcb);
    if (!srv->listen_pcb) { tcp_close(pcb); return false; }

    tcp_arg(srv->listen_pcb, srv);
    tcp_accept(srv->listen_pcb, pico_accept_cb);

    printf("[bmw] HTTP server listening on port %u\n", port);
    return true;
}

void bmw_pico_add_route(bmw_pico_server_t *srv, const char *prefix, bool exact,
                        bmw_pico_route_handler_t handler, void *ctx) {
    if (srv->route_count >= BMW_PICO_MAX_ROUTES) return;
    bmw_pico_route_t *r = &srv->routes[srv->route_count++];
    snprintf(r->prefix, sizeof(r->prefix), "%s", prefix);
    r->handler = handler;
    r->ctx = ctx;
    r->exact = exact;
}
