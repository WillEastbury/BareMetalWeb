/*
 * HTTP Router - path matching and route dispatch
 */
#include "bmw_http.h"

int bmw_router_add(bmw_router_t *router, const char *path, bmw_http_method_t method,
                   bmw_route_handler_t handler, void *userdata, bool prefix) {
    if (router->count >= BMW_MAX_ROUTES) return -1;

    bmw_route_t *r = &router->routes[router->count++];
    strncpy(r->path, path, BMW_MAX_PATH - 1);
    r->path[BMW_MAX_PATH - 1] = '\0';
    r->method = method;
    r->handler = handler;
    r->userdata = userdata;
    r->prefix_match = prefix;
    return 0;
}

bmw_route_t *bmw_router_match(bmw_router_t *router, const char *path, bmw_http_method_t method) {
    /* First pass: exact match */
    for (int i = 0; i < router->count; i++) {
        bmw_route_t *r = &router->routes[i];
        if (r->method != method && r->method != BMW_HTTP_UNKNOWN) continue;
        if (!r->prefix_match && strcmp(r->path, path) == 0)
            return r;
    }

    /* Second pass: prefix match (longest first) */
    bmw_route_t *best = NULL;
    size_t best_len = 0;
    for (int i = 0; i < router->count; i++) {
        bmw_route_t *r = &router->routes[i];
        if (r->method != method && r->method != BMW_HTTP_UNKNOWN) continue;
        if (!r->prefix_match) continue;
        size_t plen = strlen(r->path);
        if (strncmp(r->path, path, plen) == 0 && plen > best_len) {
            best = r;
            best_len = plen;
        }
    }
    return best;
}
