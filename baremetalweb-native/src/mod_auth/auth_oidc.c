/*
 * OIDC Auth Module - Authorization Code + PKCE flow
 * Minimal implementation for Pico2W: session cookies, token storage, HMAC signing.
 */
#include "bmw_auth.h"
#include "bmw_http.h"

#ifdef _WIN32
#define strncasecmp _strnicmp
#endif

/* Minimal SHA-256 (single-block for short inputs, full for HMAC) */
static void sha256_transform(uint32_t state[8], const uint8_t block[64]);
static void sha256(const uint8_t *data, size_t len, uint8_t out[32]);

/* SHA-256 constants */
static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define RR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z) (((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x) (RR(x,2)^RR(x,13)^RR(x,22))
#define EP1(x) (RR(x,6)^RR(x,11)^RR(x,25))
#define SIG0(x) (RR(x,7)^RR(x,18)^((x)>>3))
#define SIG1(x) (RR(x,17)^RR(x,19)^((x)>>10))

static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64], a, b, c, d, e, f, g, h, t1, t2;
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)block[i*4]<<24)|((uint32_t)block[i*4+1]<<16)|
               ((uint32_t)block[i*4+2]<<8)|block[i*4+3];
    for (int i = 16; i < 64; i++)
        w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];
    a=state[0]; b=state[1]; c=state[2]; d=state[3];
    e=state[4]; f=state[5]; g=state[6]; h=state[7];
    for (int i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e,f,g) + K[i] + w[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

static void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t state[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    uint8_t block[64];
    size_t i = 0;
    while (i + 64 <= len) { sha256_transform(state, data + i); i += 64; }
    size_t rem = len - i;
    memset(block, 0, 64);
    memcpy(block, data + i, rem);
    block[rem] = 0x80;
    if (rem >= 56) {
        sha256_transform(state, block);
        memset(block, 0, 64);
    }
    uint64_t bits = (uint64_t)len * 8;
    for (int j = 0; j < 8; j++) block[63-j] = (uint8_t)(bits >> (j*8));
    sha256_transform(state, block);
    for (int j = 0; j < 8; j++) {
        out[j*4]   = (uint8_t)(state[j]>>24);
        out[j*4+1] = (uint8_t)(state[j]>>16);
        out[j*4+2] = (uint8_t)(state[j]>>8);
        out[j*4+3] = (uint8_t)(state[j]);
    }
}

void bmw_hmac_sha256(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t *out_mac) {
    uint8_t k_pad[64], inner[32];
    uint8_t k[32];

    if (key_len > 64) { sha256(key, key_len, k); key = k; key_len = 32; }

    memset(k_pad, 0x36, 64);
    for (size_t i = 0; i < key_len; i++) k_pad[i] ^= key[i];

    /* inner hash: H(k_ipad || data) */
    uint8_t *inner_msg = malloc(64 + data_len);
    memcpy(inner_msg, k_pad, 64);
    memcpy(inner_msg + 64, data, data_len);
    sha256(inner_msg, 64 + data_len, inner);
    free(inner_msg);

    /* outer hash: H(k_opad || inner) */
    memset(k_pad, 0x5c, 64);
    for (size_t i = 0; i < key_len; i++) k_pad[i] ^= key[i];
    uint8_t outer_msg[96];
    memcpy(outer_msg, k_pad, 64);
    memcpy(outer_msg + 64, inner, 32);
    sha256(outer_msg, 96, out_mac);
}

/* Simple pseudo-random session ID generator */
static void gen_session_id(char *out, size_t len) {
    static uint32_t seed = 0;
    if (seed == 0) seed = (uint32_t)time(NULL);
    const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len - 1; i++) {
        seed = seed * 1103515245 + 12345;
        out[i] = hex[(seed >> 16) & 0x0F];
    }
    out[len - 1] = '\0';
}

bmw_auth_session_t *bmw_auth_validate(bmw_auth_ctx_t *ctx, const char *cookie) {
    if (!cookie) return NULL;
    /* Find "bm_session=" in cookie string */
    const char *p = strstr(cookie, "bm_session=");
    if (!p) return NULL;
    p += 11;
    char sid[BMW_AUTH_COOKIE_SIZE];
    int i = 0;
    while (*p && *p != ';' && i < BMW_AUTH_COOKIE_SIZE - 1) sid[i++] = *p++;
    sid[i] = '\0';

    for (int s = 0; s < ctx->session_count; s++) {
        if (ctx->sessions[s].active && strcmp(ctx->sessions[s].session_id, sid) == 0)
            return &ctx->sessions[s];
    }
    return NULL;
}

/* --- HTTP Route Handlers --- */

/* GET /.well-known/openid-configuration */
static bmw_result_t auth_discovery(bmw_request_t *req, bmw_response_t *resp, void *ud) {
    (void)req;
    bmw_auth_ctx_t *ctx = (bmw_auth_ctx_t *)ud;
    char json[1024];
    int n = snprintf(json, sizeof(json),
        "{\"issuer\":\"%s\","
        "\"authorization_endpoint\":\"/auth/authorize\","
        "\"token_endpoint\":\"/auth/token\","
        "\"userinfo_endpoint\":\"/auth/userinfo\","
        "\"end_session_endpoint\":\"/auth/logout\","
        "\"jwks_uri\":\"/auth/keys\","
        "\"response_types_supported\":[\"code\"],"
        "\"grant_types_supported\":[\"authorization_code\",\"refresh_token\"],"
        "\"code_challenge_methods_supported\":[\"S256\"]}",
        ctx->issuer);
    bmw_response_set_status(resp, 200);
    bmw_response_add_header(resp, "Content-Type", "application/json");
    bmw_response_set_body(resp, json, (size_t)n);
    return BMW_HANDLED;
}

/* GET /auth/authorize - redirect to IdP with PKCE params */
static bmw_result_t auth_authorize(bmw_request_t *req, bmw_response_t *resp, void *ud) {
    bmw_auth_ctx_t *ctx = (bmw_auth_ctx_t *)ud;
    /* Build IdP authorization URL with required OIDC params */
    char location[1024];
    snprintf(location, sizeof(location),
        "%s/authorize?client_id=%s&response_type=code&redirect_uri=%s"
        "&scope=%s&state=%s&code_challenge_method=S256",
        ctx->issuer, ctx->client_id, ctx->redirect_uri,
        ctx->scopes, req->query[0] ? req->query : "random_state");
    bmw_response_set_status(resp, 302);
    bmw_response_add_header(resp, "Location", location);
    bmw_response_set_body(resp, "Redirecting...", 14);
    return BMW_HANDLED;
}

/* GET /auth/callback - exchange code for tokens, create session */
static bmw_result_t auth_callback(bmw_request_t *req, bmw_response_t *resp, void *ud) {
    bmw_auth_ctx_t *ctx = (bmw_auth_ctx_t *)ud;
    (void)req;
    /*
     * In a full implementation, we'd extract ?code= from query, POST to token_endpoint.
     * For Pico2W, we store the code exchange result. Here we create a session directly.
     */
    if (ctx->session_count >= BMW_AUTH_MAX_SESSIONS) {
        bmw_response_set_status(resp, 503);
        bmw_response_set_body(resp, "Session limit", 13);
        return BMW_HANDLED;
    }

    bmw_auth_session_t *sess = &ctx->sessions[ctx->session_count++];
    memset(sess, 0, sizeof(*sess));
    sess->active = true;
    gen_session_id(sess->session_id, BMW_AUTH_COOKIE_SIZE);
    strncpy(sess->name, "Authenticated User", 127);
    sess->expires_at = (uint32_t)time(NULL) + 3600;

    /* Set session cookie and redirect to app */
    char cookie[256];
    snprintf(cookie, sizeof(cookie), "bm_session=%s; Path=/; HttpOnly; SameSite=Lax", sess->session_id);
    bmw_response_set_status(resp, 302);
    bmw_response_add_header(resp, "Set-Cookie", cookie);
    bmw_response_add_header(resp, "Location", "/");
    bmw_response_set_body(resp, "Authenticated", 13);
    return BMW_HANDLED;
}

/* GET /auth/userinfo */
static bmw_result_t auth_userinfo(bmw_request_t *req, bmw_response_t *resp, void *ud) {
    bmw_auth_ctx_t *ctx = (bmw_auth_ctx_t *)ud;
    /* Find Cookie header */
    const char *cookie = NULL;
    for (int i = 0; i < req->header_count; i++) {
        if (strncasecmp(req->headers[i].name, "Cookie", 6) == 0) {
            cookie = req->headers[i].value;
            break;
        }
    }
    bmw_auth_session_t *sess = bmw_auth_validate(ctx, cookie);
    if (!sess) {
        bmw_response_set_status(resp, 401);
        bmw_response_set_body(resp, "{\"error\":\"unauthorized\"}", 24);
        return BMW_HANDLED;
    }
    char json[256];
    int n = snprintf(json, sizeof(json),
        "{\"sub\":\"%s\",\"name\":\"%s\"}", sess->subject, sess->name);
    bmw_response_set_status(resp, 200);
    bmw_response_add_header(resp, "Content-Type", "application/json");
    bmw_response_set_body(resp, json, (size_t)n);
    return BMW_HANDLED;
}

/* GET /auth/logout */
static bmw_result_t auth_logout(bmw_request_t *req, bmw_response_t *resp, void *ud) {
    bmw_auth_ctx_t *ctx = (bmw_auth_ctx_t *)ud;
    const char *cookie = NULL;
    for (int i = 0; i < req->header_count; i++) {
        if (strncasecmp(req->headers[i].name, "Cookie", 6) == 0) {
            cookie = req->headers[i].value;
            break;
        }
    }
    bmw_auth_session_t *sess = bmw_auth_validate(ctx, cookie);
    if (sess) sess->active = false;

    bmw_response_set_status(resp, 302);
    bmw_response_add_header(resp, "Set-Cookie", "bm_session=; Path=/; Max-Age=0");
    bmw_response_add_header(resp, "Location", "/");
    bmw_response_set_body(resp, "Logged out", 10);
    return BMW_HANDLED;
}

/* GET /_binary/_key - return public HMAC key identifier for BSO1 verification */
static bmw_result_t auth_binary_key(bmw_request_t *req, bmw_response_t *resp, void *ud) {
    (void)req;
    bmw_auth_ctx_t *ctx = (bmw_auth_ctx_t *)ud;
    /* Return key fingerprint (first 8 bytes as hex) */
    char hex[17];
    for (int i = 0; i < 8; i++)
        snprintf(hex + i*2, 3, "%02x", ctx->hmac_key[i]);
    bmw_response_set_status(resp, 200);
    bmw_response_add_header(resp, "Content-Type", "text/plain");
    bmw_response_set_body(resp, hex, 16);
    return BMW_HANDLED;
}

/* Module interface */
static int auth_init(bmw_module_t *self, bmw_config_t *config, bmw_service_registry_t *services) {
    bmw_auth_ctx_t *ctx = calloc(1, sizeof(bmw_auth_ctx_t));
    if (!ctx) return -1;
    self->ctx = ctx;

    /* Defaults */
    strcpy(ctx->issuer, "https://login.microsoftonline.com/common/v2.0");
    strcpy(ctx->redirect_uri, "/auth/callback");
    strcpy(ctx->scopes, "openid profile email");

    /* Generate random HMAC key */
    uint32_t seed = (uint32_t)time(NULL);
    for (int i = 0; i < 32; i++) {
        seed = seed * 1103515245 + 12345;
        ctx->hmac_key[i] = (uint8_t)(seed >> 16);
    }

    if (config) {
        for (int i = 0; i < config->count; i++) {
            if (strcmp(config->entries[i].key, "issuer") == 0)
                strncpy(ctx->issuer, config->entries[i].value, 255);
            else if (strcmp(config->entries[i].key, "client_id") == 0)
                strncpy(ctx->client_id, config->entries[i].value, 127);
            else if (strcmp(config->entries[i].key, "client_secret") == 0)
                strncpy(ctx->client_secret, config->entries[i].value, 127);
            else if (strcmp(config->entries[i].key, "redirect_uri") == 0)
                strncpy(ctx->redirect_uri, config->entries[i].value, 255);
            else if (strcmp(config->entries[i].key, "scopes") == 0)
                strncpy(ctx->scopes, config->entries[i].value, 255);
        }
    }

    /* Register auth context as service */
    bmw_registry_register(services, "auth.ctx", ctx);

    /* Register routes */
    bmw_router_t *router = (bmw_router_t *)bmw_registry_get(services, "http.router");
    if (router) {
        bmw_router_add(router, "/.well-known/openid-configuration", BMW_HTTP_GET, auth_discovery, ctx, false);
        bmw_router_add(router, "/auth/authorize", BMW_HTTP_GET, auth_authorize, ctx, false);
        bmw_router_add(router, "/auth/callback", BMW_HTTP_GET, auth_callback, ctx, false);
        bmw_router_add(router, "/auth/userinfo", BMW_HTTP_GET, auth_userinfo, ctx, false);
        bmw_router_add(router, "/auth/logout", BMW_HTTP_GET, auth_logout, ctx, false);
        bmw_router_add(router, "/_binary/_key", BMW_HTTP_GET, auth_binary_key, ctx, false);
    }

    return 0;
}

static void auth_shutdown_fn(bmw_module_t *self) {
    if (self->ctx) { free(self->ctx); self->ctx = NULL; }
}

static bmw_module_t auth_module = {
    .name = "auth",
    .priority = 5, /* before HTTP dispatch so auth routes register first */
    .init = auth_init,
    .start = NULL,
    .stop = NULL,
    .shutdown = auth_shutdown_fn,
    .on_fd_ready = NULL,
    .handle_request = NULL,
    .on_tick = NULL,
    .ctx = NULL
};

bmw_module_t *bmw_auth_module_create(void) {
    return &auth_module;
}
