/*
 * HTTP request parser - lightweight HTTP/1.1 parser
 */
#include "bmw_http.h"
#include <errno.h>
#include <stdlib.h>

#ifdef _WIN32
#define strncasecmp _strnicmp
#endif

static bmw_http_method_t parse_method(const char *s, int len) {
    if (len == 3 && memcmp(s, "GET", 3) == 0) return BMW_HTTP_GET;
    if (len == 4 && memcmp(s, "POST", 4) == 0) return BMW_HTTP_POST;
    if (len == 3 && memcmp(s, "PUT", 3) == 0) return BMW_HTTP_PUT;
    if (len == 6 && memcmp(s, "DELETE", 6) == 0) return BMW_HTTP_DELETE;
    if (len == 4 && memcmp(s, "HEAD", 4) == 0) return BMW_HTTP_HEAD;
    if (len == 7 && memcmp(s, "OPTIONS", 7) == 0) return BMW_HTTP_OPTIONS;
    return BMW_HTTP_UNKNOWN;
}

/*
 * Parse an HTTP request from a buffer.
 * Returns bytes consumed on success, 0 if incomplete, -1 on error.
 */
int bmw_http_parse_request(const char *buf, size_t len, bmw_request_t *req) {
    memset(req, 0, sizeof(*req));
    req->keep_alive = true;
    bool cl_seen = false;
    long cl_value = -1;

    /* Find end of headers */
    const char *end = NULL;
    for (size_t i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') {
            end = &buf[i + 4];
            break;
        }
    }
    if (!end) return 0; /* incomplete */

    const char *p = buf;

    /* Method */
    const char *method_end = memchr(p, ' ', end - p);
    if (!method_end) return -1;
    req->method = parse_method(p, (int)(method_end - p));
    p = method_end + 1;

    /* Path (and optional query string) */
    const char *path_end = memchr(p, ' ', end - p);
    if (!path_end) return -1;

    /*
     * Hardened length handling: reject (caller maps -1 → 400) instead of
     * silently truncating. Truncation creates routing/auth confusion because
     * the path/query/header value seen by handlers differs from what the
     * client sent. A future request with `/admin/very-long-segment-...-extra`
     * could collapse to `/admin/very-long-segment` and bypass an exact-prefix
     * check; that class of bug is closed by hard-rejecting the request here.
     */
    const char *query = memchr(p, '?', path_end - p);
    if (query) {
        size_t plen = (size_t)(query - p);
        if (plen >= BMW_MAX_PATH) return -1;
        memcpy(req->path, p, plen);
        req->path[plen] = '\0';

        size_t qlen = (size_t)(path_end - query - 1);
        if (qlen >= BMW_MAX_PATH) return -1;
        memcpy(req->query, query + 1, qlen);
        req->query[qlen] = '\0';
    } else {
        size_t plen = (size_t)(path_end - p);
        if (plen >= BMW_MAX_PATH) return -1;
        memcpy(req->path, p, plen);
        req->path[plen] = '\0';
    }

    /* Normalize path: reject traversal */
    if (strstr(req->path, "..")) return -1;

    /* Skip HTTP version line */
    const char *line_end = memchr(path_end, '\n', end - path_end);
    if (!line_end) return -1;
    p = line_end + 1;

    /* Headers */
    while (p < end - 2) {
        if (p[0] == '\r' && p[1] == '\n') break;
        const char *colon = memchr(p, ':', end - p);
        if (!colon) break;

        line_end = memchr(p, '\n', end - p);
        if (!line_end) break;

        if (req->header_count < BMW_MAX_HEADERS) {
            size_t nlen = (size_t)(colon - p);
            if (nlen >= sizeof(req->headers[0].name)) return -1;
            memcpy(req->headers[req->header_count].name, p, nlen);
            req->headers[req->header_count].name[nlen] = '\0';

            const char *val = colon + 1;
            while (val < line_end && *val == ' ') val++;
            size_t vlen = (size_t)(line_end - val);
            if (vlen > 0 && val[vlen-1] == '\r') vlen--;
            if (vlen >= BMW_MAX_HEADER_VAL) return -1;
            memcpy(req->headers[req->header_count].value, val, vlen);
            req->headers[req->header_count].value[vlen] = '\0';

            /* Check for content-length and connection */
            /*
             * HTTP/1.1 framing hardening (request smuggling defence):
             *   - Reject Transfer-Encoding entirely (we don't implement chunked).
             *     If we ever sit behind a proxy that DOES, divergent framing
             *     between the front-end and us is the classic CL.TE/TE.CL bug.
             *   - Reject duplicate Content-Length unless byte-identical.
             *   - Parse Content-Length strictly with strtoul + full consumption,
             *     not atol() (which silently accepts " 10garbage" and overflow).
             */
            if (nlen == 17 && strncasecmp(req->headers[req->header_count].name, "Transfer-Encoding", 17) == 0) {
                return -1;
            }
            if (nlen == 14 && strncasecmp(req->headers[req->header_count].name, "Content-Length", 14) == 0) {
                const char *cv = req->headers[req->header_count].value;
                if (!*cv) return -1;
                char *endp = NULL;
                errno = 0;
                unsigned long ul = strtoul(cv, &endp, 10);
                if (errno == ERANGE || !endp || *endp != '\0') return -1;
                if (ul > 1048576UL) return -1; /* 1 MB cap */
                long cl = (long)ul;
                if (cl_seen) {
                    if (cl != cl_value) return -1; /* conflicting CLs */
                } else {
                    cl_seen = true;
                    cl_value = cl;
                    req->content_length = (size_t)cl;
                }
            }
            if (nlen == 10 && strncasecmp(req->headers[req->header_count].name, "Connection", 10) == 0) {
                if (strncasecmp(req->headers[req->header_count].value, "close", 5) == 0)
                    req->keep_alive = false;
            }

            req->header_count++;
        }
        p = line_end + 1;
    }

    size_t header_len = (size_t)(end - buf);

    /* Body handling */
    if (req->content_length > 0) {
        if (len - header_len < req->content_length) return 0; /* incomplete body */
        req->body = (char *)(buf + header_len);
        req->body_len = req->content_length;
        return (int)(header_len + req->content_length);
    }

    return (int)header_len;
}

