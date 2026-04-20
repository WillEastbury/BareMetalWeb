#ifndef BMW_AUTH_H
#define BMW_AUTH_H

#include "bmw_module.h"

/*
 * OIDC Auth Module
 * Implements OAuth2 Authorization Code + PKCE flow endpoints:
 *   /.well-known/openid-configuration  (discovery)
 *   /auth/authorize                    (redirect to IdP)
 *   /auth/callback                     (code exchange)
 *   /auth/token                        (token endpoint / refresh)
 *   /auth/userinfo                     (proxy to IdP userinfo)
 *   /auth/logout                       (end session)
 *   /auth/silent                       (silent refresh iframe)
 *
 * Config keys:
 *   issuer          - OIDC issuer URL (e.g. https://login.microsoftonline.com/{tenant}/v2.0)
 *   client_id       - App registration client ID
 *   client_secret   - App secret (optional for public clients)
 *   redirect_uri    - Callback URI (default: /auth/callback)
 *   scopes          - Space-separated scopes (default: openid profile email)
 *   hmac_key        - 32-byte hex key for BSO1 signing + session cookies
 */

#define BMW_AUTH_MAX_SESSIONS 16
#define BMW_AUTH_TOKEN_SIZE   512
#define BMW_AUTH_COOKIE_SIZE  64

typedef struct {
    char session_id[BMW_AUTH_COOKIE_SIZE];
    char access_token[BMW_AUTH_TOKEN_SIZE];
    char refresh_token[BMW_AUTH_TOKEN_SIZE];
    char id_token[BMW_AUTH_TOKEN_SIZE];
    char subject[128];
    char name[128];
    uint32_t expires_at;
    bool active;
} bmw_auth_session_t;

typedef struct {
    char issuer[256];
    char client_id[128];
    char client_secret[128];
    char redirect_uri[256];
    char scopes[256];
    uint8_t hmac_key[32];
    bmw_auth_session_t sessions[BMW_AUTH_MAX_SESSIONS];
    int session_count;
    /* Pending auth state nonces (CSRF protection) */
    char pending_states[BMW_AUTH_MAX_SESSIONS][BMW_AUTH_COOKIE_SIZE];
    int pending_state_count;
} bmw_auth_ctx_t;

bmw_module_t *bmw_auth_module_create(void);

/* Utility: validate a request's auth cookie, return session or NULL */
bmw_auth_session_t *bmw_auth_validate(bmw_auth_ctx_t *ctx, const char *cookie);

/* Utility: HMAC-SHA256 for BSO1 signing */
void bmw_hmac_sha256(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t *out_mac);

#endif /* BMW_AUTH_H */
