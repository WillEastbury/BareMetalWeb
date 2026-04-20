#ifndef BMW_MODULE_H
#define BMW_MODULE_H

#include "bmw_platform.h"
#include "bmw_event_loop.h"

/* Forward declarations */
typedef struct bmw_request bmw_request_t;
typedef struct bmw_response bmw_response_t;
typedef struct bmw_module bmw_module_t;
typedef struct bmw_service_registry bmw_service_registry_t;

/* Module handler return codes */
typedef enum {
    BMW_DECLINED = 0,   /* Module didn't handle this request */
    BMW_HANDLED = 1,    /* Module handled the request fully */
    BMW_ERROR   = -1    /* Module encountered an error */
} bmw_result_t;

/* Module configuration */
typedef struct {
    const char *key;
    const char *value;
} bmw_config_entry_t;

typedef struct {
    bmw_config_entry_t *entries;
    int count;
} bmw_config_t;

/* Module interface */
struct bmw_module {
    const char *name;
    int priority; /* lower = earlier in chain */

    int  (*init)(bmw_module_t *self, bmw_config_t *config, bmw_service_registry_t *services);
    int  (*start)(bmw_module_t *self, bmw_event_loop_t *loop);
    void (*stop)(bmw_module_t *self);
    void (*shutdown)(bmw_module_t *self);

    /* Called when a registered fd has activity */
    void (*on_fd_ready)(bmw_module_t *self, bmw_socket_t fd, int events);

    /* HTTP request handler (only for HTTP-facing modules) */
    bmw_result_t (*handle_request)(bmw_module_t *self, bmw_request_t *req, bmw_response_t *resp);

    /* Periodic tick (called each event loop iteration) */
    void (*on_tick)(bmw_module_t *self);

    void *ctx; /* module-private context */
};

/* Service registry: modules expose named services */
struct bmw_service_registry {
    struct { const char *name; void *service; } entries[16];
    int count;
};

void bmw_registry_register(bmw_service_registry_t *reg, const char *name, void *service);
void *bmw_registry_get(bmw_service_registry_t *reg, const char *name);

/* Module system */
#define BMW_MAX_MODULES 8

typedef struct {
    bmw_module_t *modules[BMW_MAX_MODULES];
    int count;
    bmw_service_registry_t services;
    bmw_event_loop_t *loop;
} bmw_app_t;

int  bmw_app_init(bmw_app_t *app);
int  bmw_app_add_module(bmw_app_t *app, bmw_module_t *mod, bmw_config_t *config);
int  bmw_app_start(bmw_app_t *app);
void bmw_app_stop(bmw_app_t *app);
void bmw_app_shutdown(bmw_app_t *app);
bmw_result_t bmw_app_dispatch(bmw_app_t *app, bmw_request_t *req, bmw_response_t *resp);
void bmw_app_tick(bmw_app_t *app);

#endif /* BMW_MODULE_H */
