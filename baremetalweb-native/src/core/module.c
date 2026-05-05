/*
 * Module system - registration, lifecycle, dispatch
 */
#include "bmw_module.h"
#include "bmw_event_loop.h"

void bmw_registry_register(bmw_service_registry_t *reg, const char *name, void *service) {
    if (reg->count >= 16) return;
    reg->entries[reg->count].name = name;
    reg->entries[reg->count].service = service;
    reg->count++;
}

void *bmw_registry_get(bmw_service_registry_t *reg, const char *name) {
    for (int i = 0; i < reg->count; i++) {
        if (strcmp(reg->entries[i].name, name) == 0)
            return reg->entries[i].service;
    }
    return NULL;
}

int bmw_app_init(bmw_app_t *app) {
    memset(app, 0, sizeof(*app));
    return 0;
}

int bmw_app_add_module(bmw_app_t *app, bmw_module_t *mod, bmw_config_t *config) {
    if (app->count >= BMW_MAX_MODULES) return -1;

    if (mod->init) {
        int rc = mod->init(mod, config, &app->services);
        if (rc != 0) return rc;
    }

    /* Insert sorted by priority */
    int pos = app->count;
    for (int i = 0; i < app->count; i++) {
        if (mod->priority < app->modules[i]->priority) {
            pos = i;
            break;
        }
    }
    for (int i = app->count; i > pos; i--)
        app->modules[i] = app->modules[i - 1];
    app->modules[pos] = mod;
    app->count++;
    return 0;
}

int bmw_app_start(bmw_app_t *app) {
    for (int i = 0; i < app->count; i++) {
        if (app->modules[i]->start) {
            int rc = app->modules[i]->start(app->modules[i], app->loop);
            if (rc != 0) {
                /* Unwind: stop modules 0..i-1 in reverse so partial-start
                 * doesn't leave listening sockets / WAL handles / event-loop
                 * registrations dangling for the caller to leak on exit. */
                for (int j = i - 1; j >= 0; j--) {
                    if (app->modules[j]->stop)
                        app->modules[j]->stop(app->modules[j]);
                }
                return rc;
            }
        }
    }
    return 0;
}

void bmw_app_stop(bmw_app_t *app) {
    for (int i = app->count - 1; i >= 0; i--) {
        if (app->modules[i]->stop)
            app->modules[i]->stop(app->modules[i]);
    }
}

void bmw_app_shutdown(bmw_app_t *app) {
    for (int i = app->count - 1; i >= 0; i--) {
        if (app->modules[i]->shutdown)
            app->modules[i]->shutdown(app->modules[i]);
    }
}

bmw_result_t bmw_app_dispatch(bmw_app_t *app, bmw_request_t *req, bmw_response_t *resp) {
    for (int i = 0; i < app->count; i++) {
        if (app->modules[i]->handle_request) {
            bmw_result_t rc = app->modules[i]->handle_request(app->modules[i], req, resp);
            if (rc != BMW_DECLINED) return rc;
        }
    }
    return BMW_DECLINED;
}

void bmw_app_tick(bmw_app_t *app) {
    for (int i = 0; i < app->count; i++) {
        if (app->modules[i]->on_tick)
            app->modules[i]->on_tick(app->modules[i]);
    }
}
