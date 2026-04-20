#ifndef BMW_HTTP_H
#define BMW_HTTP_H

#include "bmw_module.h"

#define BMW_MAX_HEADERS     16
#define BMW_MAX_PATH        128
#define BMW_MAX_METHOD      8
#define BMW_MAX_HEADER_VAL  256
#define BMW_READ_BUF_SIZE   1024
#ifdef BMW_PICO_BUILD
#define BMW_WRITE_BUF_SIZE  4096
#define BMW_MAX_CONNECTIONS 4
#else
#define BMW_WRITE_BUF_SIZE  65536
#define BMW_MAX_CONNECTIONS 8
#endif
#define BMW_MAX_ROUTES      16

/* HTTP methods */
typedef enum {
    BMW_HTTP_GET = 0,
    BMW_HTTP_POST,
    BMW_HTTP_PUT,
    BMW_HTTP_DELETE,
    BMW_HTTP_HEAD,
    BMW_HTTP_OPTIONS,
    BMW_HTTP_UNKNOWN
} bmw_http_method_t;

/* HTTP header */
typedef struct {
    char name[32];
    char value[BMW_MAX_HEADER_VAL];
} bmw_header_t;

/* HTTP request */
struct bmw_request {
    bmw_http_method_t method;
    char path[BMW_MAX_PATH];
    char query[BMW_MAX_PATH];
    bmw_header_t headers[BMW_MAX_HEADERS];
    int header_count;
    char *body;
    size_t body_len;
    size_t content_length;
    bool keep_alive;
};

/* HTTP response */
struct bmw_response {
    int status;
    bmw_header_t headers[BMW_MAX_HEADERS];
    int header_count;
    char *body;
    size_t body_len;
    size_t body_cap;
    bool headers_sent;
};

/* Route handler */
typedef bmw_result_t (*bmw_route_handler_t)(bmw_request_t *req, bmw_response_t *resp, void *userdata);

typedef struct {
    char path[BMW_MAX_PATH];
    bmw_http_method_t method;
    bmw_route_handler_t handler;
    void *userdata;
    bool prefix_match;
} bmw_route_t;

/* HTTP module public API */
bmw_module_t *bmw_http_module_create(void);

/* Router API (used by other modules to register routes) */
typedef struct {
    bmw_route_t routes[BMW_MAX_ROUTES];
    int count;
} bmw_router_t;

int bmw_router_add(bmw_router_t *router, const char *path, bmw_http_method_t method,
                   bmw_route_handler_t handler, void *userdata, bool prefix);
bmw_route_t *bmw_router_match(bmw_router_t *router, const char *path, bmw_http_method_t method);

/* Response helpers */
void bmw_response_init(bmw_response_t *resp);
void bmw_response_set_status(bmw_response_t *resp, int status);
void bmw_response_add_header(bmw_response_t *resp, const char *name, const char *value);
void bmw_response_set_body(bmw_response_t *resp, const char *body, size_t len);
void bmw_response_append_body(bmw_response_t *resp, const char *data, size_t len);
void bmw_response_free(bmw_response_t *resp);

/* Template engine */
typedef struct {
    const char *key;
    const char *value;
} bmw_template_var_t;

int bmw_template_render(const char *tmpl, size_t tmpl_len,
                        bmw_template_var_t *vars, int var_count,
                        char *output, size_t output_cap, size_t *output_len);

/* Static file serving */
int bmw_static_serve(const char *root_dir, const char *path,
                     bmw_response_t *resp);

#endif /* BMW_HTTP_H */
