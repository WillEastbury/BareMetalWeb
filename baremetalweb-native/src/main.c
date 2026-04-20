/*
 * BareMetalWeb Native - Main entry point
 * Boots the module system, registers HTTP + WAL modules, runs event loop.
 */
#include "bmw_platform.h"
#include "bmw_module.h"
#include "bmw_event_loop.h"
#include "bmw_http.h"
#include "bmw_wal.h"
#include "bmw_auth.h"
#include "bmw_meta.h"
#include "bmw_ws.h"

#include <signal.h>

static bmw_app_t app;
static bmw_event_loop_t loop;

#ifdef _WIN32
static BOOL WINAPI signal_handler(DWORD sig) {
    (void)sig;
    printf("\n[BMW] Shutting down...\n");
    bmw_loop_stop(&loop);
    return TRUE;
}
#else
static void signal_handler(int sig) {
    (void)sig;
    printf("\n[BMW] Shutting down...\n");
    bmw_loop_stop(&loop);
}
#endif

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    printf("BareMetalWeb Native v1.0\n");
    printf("========================\n");

    /* Platform init */
    bmw_platform_init();

    /* Event loop */
    if (bmw_loop_init(&loop) != 0) {
        fprintf(stderr, "Failed to initialize event loop\n");
        return 1;
    }

    /* App init */
    bmw_app_init(&app);
    app.loop = &loop;

    /* Configure HTTP module */
    bmw_config_entry_t http_entries[] = {
        { "port", "8080" },
        { "static_root", "./wwwroot" }
    };
    bmw_config_t http_config = { http_entries, 2 };

    /* Configure Auth module */
    bmw_config_entry_t auth_entries[] = {
        { "issuer", "https://login.microsoftonline.com/common/v2.0" },
        { "client_id", "your-client-id" },
        { "redirect_uri", "/auth/callback" },
        { "scopes", "openid profile email" }
    };
    bmw_config_t auth_config = { auth_entries, 4 };

    /* Configure WAL module */
    bmw_config_entry_t wal_entries[] = {
        { "tcp_port", "8001" },
        { "tcp_enabled", "true" }
    };
    bmw_config_t wal_config = { wal_entries, 2 };

    /* Register modules (order matters: HTTP first, then auth, meta, ws, wal) */
    bmw_module_t *http_mod = bmw_http_module_create();
    bmw_module_t *auth_mod = bmw_auth_module_create();
    bmw_module_t *meta_mod = bmw_meta_module_create();
    bmw_module_t *ws_mod   = bmw_ws_module_create();
    bmw_module_t *wal_mod  = bmw_wal_module_create();

    if (bmw_app_add_module(&app, http_mod, &http_config) != 0) {
        fprintf(stderr, "Failed to init HTTP module\n");
        return 1;
    }
    if (bmw_app_add_module(&app, auth_mod, &auth_config) != 0) {
        fprintf(stderr, "Failed to init Auth module\n");
        return 1;
    }
    if (bmw_app_add_module(&app, wal_mod, &wal_config) != 0) {
        fprintf(stderr, "Failed to init WAL module\n");
        return 1;
    }
    if (bmw_app_add_module(&app, meta_mod, NULL) != 0) {
        fprintf(stderr, "Failed to init Meta module\n");
        return 1;
    }
    if (bmw_app_add_module(&app, ws_mod, NULL) != 0) {
        fprintf(stderr, "Failed to init WebSocket module\n");
        return 1;
    }

    /* Start modules */
    if (bmw_app_start(&app) != 0) {
        fprintf(stderr, "Failed to start modules\n");
        return 1;
    }

    /* Signal handling */
#ifdef _WIN32
    SetConsoleCtrlHandler(signal_handler, TRUE);
#else
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
#endif

    printf("[BMW] Server running. Press Ctrl+C to stop.\n");

    /* Run event loop */
    bmw_loop_run(&loop);

    /* Cleanup */
    bmw_app_stop(&app);
    bmw_app_shutdown(&app);
    bmw_loop_destroy(&loop);
    bmw_platform_shutdown();

    printf("[BMW] Shutdown complete.\n");
    return 0;
}
