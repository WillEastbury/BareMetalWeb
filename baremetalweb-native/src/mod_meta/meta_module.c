/*
 * Metadata & Entity API Module
 * Serves entity schemas, CRUD endpoints, BSO1 binary encoding.
 * Stores records in-memory (WAL-backed via service registry).
 */
#include "bmw_meta.h"
#include "bmw_http.h"
#include "bmw_auth.h"
#include "bmw_compress.h"

#ifdef _WIN32
#define strncasecmp _strnicmp
#endif

/* --- BSO1 Encoding --- */

int bmw_bso1_encode_record(bmw_meta_ctx_t *ctx, int entity_idx, int record_idx,
                           uint8_t *out, size_t out_cap, size_t *out_len,
                           const uint8_t *hmac_key) {
    bmw_entity_def_t *ent = &ctx->entities[entity_idx];
    bmw_record_t *rec = &ctx->records[entity_idx][record_idx];

    /* Build payload: presence byte + field values as length-prefixed strings */
    uint8_t payload[2048];
    size_t pos = 0;

    /* Presence bitmap (1 bit per field) */
    int presence_bytes = (ent->field_count + 7) / 8;
    memset(payload + pos, 0, presence_bytes);
    for (int f = 0; f < ent->field_count; f++) {
        if (rec->values[f][0] != '\0')
            payload[pos + f/8] |= (1 << (f % 8));
    }
    pos += presence_bytes;

    /* Fields: [len:u16 LE][data...] for present fields */
    for (int f = 0; f < ent->field_count; f++) {
        if (rec->values[f][0] == '\0') continue;
        uint16_t flen = (uint16_t)strlen(rec->values[f]);
        if (pos + 2 + flen > sizeof(payload)) return -1;
        memcpy(payload + pos, &flen, 2); pos += 2;
        memcpy(payload + pos, rec->values[f], flen); pos += flen;
    }

    /* BSO1 header: magic(4) + version(1) + schemaVersion(1) + reserved(2) + hmac(32) = 40 */
    if (BSO1_HEADER_LEN + pos > out_cap) return -1;

    size_t hdr_pos = 0;
    uint32_t magic = BSO1_MAGIC;
    memcpy(out + hdr_pos, &magic, 4); hdr_pos += 4;
    out[hdr_pos++] = BSO1_VERSION;
    out[hdr_pos++] = 1; /* schema version */
    out[hdr_pos++] = 0; /* reserved */
    out[hdr_pos++] = 0;
    /* HMAC placeholder - computed over payload */
    if (hmac_key) {
        bmw_hmac_sha256(hmac_key, 32, payload, pos, out + hdr_pos);
    } else {
        memset(out + hdr_pos, 0, 32);
    }
    hdr_pos += 32;

    memcpy(out + hdr_pos, payload, pos);
    *out_len = hdr_pos + pos;
    return 0;
}

int bmw_bso1_encode_list(bmw_meta_ctx_t *ctx, int entity_idx,
                         uint8_t *out, size_t out_cap, size_t *out_len,
                         const uint8_t *hmac_key) {
    /* Use static scratch buffers to keep stack frame small (Pico-safe) */
    static uint8_t items_buf[4096];
    static uint8_t rec_buf[2048];
    size_t items_pos = 0;
    int count = 0;

    for (int r = 0; r < ctx->record_counts[entity_idx]; r++) {
        if (!ctx->records[entity_idx][r].active) continue;
        size_t rec_len = 0;
        bmw_entity_def_t *ent = &ctx->entities[entity_idx];
        bmw_record_t *rec = &ctx->records[entity_idx][r];

        size_t pos = 0;
        int pb = (ent->field_count + 7) / 8;
        if ((size_t)pb > sizeof(rec_buf)) break;
        memset(rec_buf + pos, 0, pb);
        for (int f = 0; f < ent->field_count; f++) {
            if (rec->values[f][0]) rec_buf[pos + f/8] |= (1 << (f%8));
        }
        pos += pb;
        for (int f = 0; f < ent->field_count; f++) {
            if (!rec->values[f][0]) continue;
            uint16_t flen = (uint16_t)strlen(rec->values[f]);
            if (pos + 2 + flen > sizeof(rec_buf)) goto done_records;
            memcpy(rec_buf + pos, &flen, 2); pos += 2;
            memcpy(rec_buf + pos, rec->values[f], flen); pos += flen;
        }
        rec_len = pos;

        if (items_pos + 4 + rec_len > sizeof(items_buf)) break;
        uint32_t ilen = (uint32_t)rec_len;
        memcpy(items_buf + items_pos, &ilen, 4); items_pos += 4;
        memcpy(items_buf + items_pos, rec_buf, rec_len); items_pos += rec_len;
        count++;
    }
done_records:

    /* Build BSO1 frame */
    size_t payload_len = 4 + items_pos; /* count + items */
    if (BSO1_HEADER_LEN + payload_len > out_cap) return -1;

    size_t hdr_pos = 0;
    uint32_t magic = BSO1_MAGIC;
    memcpy(out + hdr_pos, &magic, 4); hdr_pos += 4;
    out[hdr_pos++] = BSO1_VERSION;
    out[hdr_pos++] = 1;
    out[hdr_pos++] = 0;
    out[hdr_pos++] = 0;

    /* Build payload for HMAC */
    uint8_t *payload = out + BSO1_HEADER_LEN;
    uint32_t cnt = (uint32_t)count;
    memcpy(payload, &cnt, 4);
    memcpy(payload + 4, items_buf, items_pos);

    if (hmac_key) {
        bmw_hmac_sha256(hmac_key, 32, payload, payload_len, out + hdr_pos);
    } else {
        memset(out + hdr_pos, 0, 32);
    }
    hdr_pos += 32;

    *out_len = hdr_pos + payload_len;
    return 0;
}

/* --- HTTP Route Handlers --- */

static bmw_meta_ctx_t *g_meta_ctx = NULL;
static uint8_t *g_hmac_key = NULL;

/* GET /api/_meta - list all entities */
static bmw_result_t meta_list_all(bmw_request_t *req, bmw_response_t *resp, void *ud) {
    (void)req;
    bmw_meta_ctx_t *ctx = (bmw_meta_ctx_t *)ud;
    char json[2048];
    int n = snprintf(json, sizeof(json), "[");
    for (int i = 0; i < ctx->entity_count; i++) {
        if (n >= (int)sizeof(json) - 1) break; /* truncation guard */
        if (i > 0) n += snprintf(json + n, sizeof(json) - n, ",");
        n += snprintf(json + n, sizeof(json) - n,
            "{\"name\":\"%s\",\"slug\":\"%s\",\"endpoint\":\"/api/%s\",\"fieldCount\":%d}",
            ctx->entities[i].name, ctx->entities[i].slug,
            ctx->entities[i].slug, ctx->entities[i].field_count);
    }
    if (n < (int)sizeof(json)) n += snprintf(json + n, sizeof(json) - n, "]");
    if (n >= (int)sizeof(json)) n = (int)sizeof(json) - 1;
    bmw_response_set_status(resp, 200);
    bmw_response_add_header(resp, "Content-Type", "application/json");
    bmw_response_set_body(resp, json, (size_t)n);
    return BMW_HANDLED;
}

/* Helper: find entity index by slug from path */
static int find_entity(bmw_meta_ctx_t *ctx, const char *path, const char *prefix) {
    const char *slug = path + strlen(prefix);
    /* Strip trailing / or /id */
    char buf[64];
    strncpy(buf, slug, 63); buf[63] = '\0';
    char *slash = strchr(buf, '/');
    if (slash) *slash = '\0';
    for (int i = 0; i < ctx->entity_count; i++) {
        if (strcmp(ctx->entities[i].slug, buf) == 0) return i;
    }
    return -1;
}

/* Extract ID from path like /api/slug/123 */
static int extract_id(const char *path, const char *prefix) {
    const char *rest = path + strlen(prefix);
    const char *slash = strchr(rest, '/');
    if (!slash) return -1;
    return atoi(slash + 1);
}

/* GET/POST /api/{slug} and /api/{slug}/{id} */
static bmw_result_t meta_api_handler(bmw_request_t *req, bmw_response_t *resp, void *ud) {
    bmw_meta_ctx_t *ctx = (bmw_meta_ctx_t *)ud;
    int eidx = find_entity(ctx, req->path, "/api/");
    if (eidx < 0) return BMW_DECLINED;

    bmw_entity_def_t *ent = &ctx->entities[eidx];

    if (req->method == BMW_HTTP_GET) {
        int id = extract_id(req->path, "/api/");
        if (id < 0) {
            /* List all records */
            char json[4096];
            int n = snprintf(json, sizeof(json), "[");
            for (int r = 0; r < ctx->record_counts[eidx]; r++) {
                if (!ctx->records[eidx][r].active) continue;
                if (n >= (int)sizeof(json) - 2) break; /* truncation guard */
                if (n > 1) n += snprintf(json+n, sizeof(json)-n, ",");
                n += snprintf(json+n, sizeof(json)-n, "{\"id\":%u", ctx->records[eidx][r].id);
                for (int f = 0; f < ent->field_count; f++) {
                    if (n >= (int)sizeof(json) - 2) break;
                    if (ctx->records[eidx][r].values[f][0])
                        n += snprintf(json+n, sizeof(json)-n, ",\"%s\":\"%s\"",
                                      ent->fields[f].name, ctx->records[eidx][r].values[f]);
                }
                n += snprintf(json+n, sizeof(json)-n, "}");
            }
            if (n < (int)sizeof(json)) n += snprintf(json+n, sizeof(json)-n, "]");
            if (n >= (int)sizeof(json)) n = (int)sizeof(json) - 1;
            bmw_response_set_status(resp, 200);
            bmw_response_add_header(resp, "Content-Type", "application/json");
            bmw_response_set_body(resp, json, (size_t)n);
        } else {
            /* Get single record */
            for (int r = 0; r < ctx->record_counts[eidx]; r++) {
                if (ctx->records[eidx][r].active && (int)ctx->records[eidx][r].id == id) {
                    char json[1024];
                    int n = snprintf(json, sizeof(json), "{\"id\":%u", ctx->records[eidx][r].id);
                    for (int f = 0; f < ent->field_count; f++) {
                        if (n >= (int)sizeof(json) - 2) break;
                        if (ctx->records[eidx][r].values[f][0])
                            n += snprintf(json+n, sizeof(json)-n, ",\"%s\":\"%s\"",
                                          ent->fields[f].name, ctx->records[eidx][r].values[f]);
                    }
                    if (n < (int)sizeof(json)) n += snprintf(json+n, sizeof(json)-n, "}");
                    if (n >= (int)sizeof(json)) n = (int)sizeof(json) - 1;
                    bmw_response_set_status(resp, 200);
                    bmw_response_add_header(resp, "Content-Type", "application/json");
                    bmw_response_set_body(resp, json, (size_t)n);
                    return BMW_HANDLED;
                }
            }
            bmw_response_set_status(resp, 404);
            bmw_response_set_body(resp, "{\"error\":\"not found\"}", 21);
        }
    } else if (req->method == BMW_HTTP_POST) {
        /* Create record - simple JSON field extraction */
        if (ctx->record_counts[eidx] >= BMW_META_MAX_RECORDS) {
            bmw_response_set_status(resp, 503);
            bmw_response_set_body(resp, "{\"error\":\"full\"}", 16);
            return BMW_HANDLED;
        }
        bmw_record_t *rec = &ctx->records[eidx][ctx->record_counts[eidx]++];
        memset(rec, 0, sizeof(*rec));
        rec->id = ctx->next_id[eidx]++;
        rec->active = true;
        /* Very basic JSON field parsing: find "field":"value" pairs */
        /* NUL-terminate body copy to safely use strstr/strchr */
        if (req->body && req->body_len > 0) {
            size_t safe_len = req->body_len < 4095 ? req->body_len : 4095;
            char body_copy[4096];
            memcpy(body_copy, req->body, safe_len);
            body_copy[safe_len] = '\0';
            for (int f = 0; f < ent->field_count; f++) {
                char pattern[80];
                snprintf(pattern, sizeof(pattern), "\"%s\":\"", ent->fields[f].name);
                const char *p = strstr(body_copy, pattern);
                if (p) {
                    p += strlen(pattern);
                    const char *end = strchr(p, '"');
                    if (end) {
                        size_t vlen = (size_t)(end - p);
                        if (vlen >= BMW_META_VALUE_SIZE) vlen = BMW_META_VALUE_SIZE - 1;
                        memcpy(rec->values[f], p, vlen);
                    }
                }
            }
        }
        char json[64];
        int n = snprintf(json, sizeof(json), "{\"id\":%u}", rec->id);
        bmw_response_set_status(resp, 201);
        bmw_response_add_header(resp, "Content-Type", "application/json");
        bmw_response_set_body(resp, json, (size_t)n);
    } else if (req->method == BMW_HTTP_DELETE) {
        int id = extract_id(req->path, "/api/");
        if (id >= 0) {
            for (int r = 0; r < ctx->record_counts[eidx]; r++) {
                if (ctx->records[eidx][r].active && (int)ctx->records[eidx][r].id == id) {
                    ctx->records[eidx][r].active = false;
                    bmw_response_set_status(resp, 204);
                    return BMW_HANDLED;
                }
            }
        }
        bmw_response_set_status(resp, 404);
        bmw_response_set_body(resp, "{\"error\":\"not found\"}", 21);
    }
    return BMW_HANDLED;
}

/* GET /api/_binary/{slug} - BSO1 encoded list */
static bmw_result_t meta_binary_handler(bmw_request_t *req, bmw_response_t *resp, void *ud) {
    bmw_meta_ctx_t *ctx = (bmw_meta_ctx_t *)ud;
    int eidx = find_entity(ctx, req->path, "/api/_binary/");
    if (eidx < 0) return BMW_DECLINED;

    uint8_t buf[4096];
    size_t len = 0;
    int rc = bmw_bso1_encode_list(ctx, eidx, buf, sizeof(buf), &len, g_hmac_key);
    if (rc != 0) {
        bmw_response_set_status(resp, 500);
        return BMW_HANDLED;
    }
    bmw_response_set_status(resp, 200);
    bmw_response_add_header(resp, "Content-Type", "application/x-bso1");
    bmw_response_set_body(resp, (const char *)buf, len);
    return BMW_HANDLED;
}

/* GET /api/metadata/{slug} - entity schema JSON */
static bmw_result_t meta_schema_handler(bmw_request_t *req, bmw_response_t *resp, void *ud) {
    bmw_meta_ctx_t *ctx = (bmw_meta_ctx_t *)ud;
    int eidx = find_entity(ctx, req->path, "/api/metadata/");
    if (eidx < 0) return BMW_DECLINED;

    bmw_entity_def_t *ent = &ctx->entities[eidx];
    char json[2048];
    int n = snprintf(json, sizeof(json),
        "{\"name\":\"%s\",\"slug\":\"%s\",\"endpoint\":\"/api/%s\","
        "\"schema\":{\"fields\":{",
        ent->name, ent->slug, ent->slug);

    for (int f = 0; f < ent->field_count; f++) {
        if (n >= (int)sizeof(json) - 2) break; /* truncation guard */
        if (f > 0) n += snprintf(json+n, sizeof(json)-n, ",");
        n += snprintf(json+n, sizeof(json)-n,
            "\"%s\":{\"type\":\"%s\",\"label\":\"%s\",\"required\":%s}",
            ent->fields[f].name,
            ent->fields[f].type == BMW_FIELD_TEXT ? "text" :
            ent->fields[f].type == BMW_FIELD_NUMBER ? "number" :
            ent->fields[f].type == BMW_FIELD_EMAIL ? "email" :
            ent->fields[f].type == BMW_FIELD_DATE ? "date" :
            ent->fields[f].type == BMW_FIELD_BOOL ? "boolean" :
            ent->fields[f].type == BMW_FIELD_SELECT ? "select" :
            ent->fields[f].type == BMW_FIELD_TEXTAREA ? "textarea" : "text",
            ent->fields[f].label,
            ent->fields[f].required ? "true" : "false");
    }
    if (n < (int)sizeof(json)) n += snprintf(json+n, sizeof(json)-n, "}},\"layout\":{\"columns\":%d}}", ent->columns);
    if (n >= (int)sizeof(json)) n = (int)sizeof(json) - 1;

    bmw_response_set_status(resp, 200);
    bmw_response_add_header(resp, "Content-Type", "application/json");
    bmw_response_set_body(resp, json, (size_t)n);
    return BMW_HANDLED;
}

/* GET /bmw/routes */
static bmw_result_t meta_routes(bmw_request_t *req, bmw_response_t *resp, void *ud) {
    (void)req; (void)ud;
    bmw_response_set_status(resp, 200);
    bmw_response_add_header(resp, "Content-Type", "application/json");
    const char *body = "{\"routes\":[\"/api\",\"/auth\",\"/bmw/ws\",\"/bmw/protocol\"]}";
    bmw_response_set_body(resp, body, strlen(body));
    return BMW_HANDLED;
}

/* GET /bmw/protocol */
static bmw_result_t meta_protocol(bmw_request_t *req, bmw_response_t *resp, void *ud) {
    (void)req; (void)ud;
    bmw_response_set_status(resp, 200);
    bmw_response_add_header(resp, "Content-Type", "application/json");
    const char *body = "{\"binary\":true,\"compression\":\"BareMetal.Compress\","
                       "\"websocket\":\"/bmw/ws\",\"bso1_version\":3}";
    bmw_response_set_body(resp, body, strlen(body));
    return BMW_HANDLED;
}

/* Module interface */
static int meta_init(bmw_module_t *self, bmw_config_t *config, bmw_service_registry_t *services) {
    (void)config;
    bmw_meta_ctx_t *ctx = calloc(1, sizeof(bmw_meta_ctx_t));
    if (!ctx) return -1;
    self->ctx = ctx;
    g_meta_ctx = ctx;

    /* Initialize next_id */
    for (int i = 0; i < BMW_META_MAX_ENTITIES; i++) ctx->next_id[i] = 1;

    /* Register a sample entity for demonstration */
    bmw_entity_def_t *ent = &ctx->entities[0];
    strcpy(ent->name, "Contact");
    strcpy(ent->slug, "contact");
    strcpy(ent->endpoint, "/api/contact");
    ent->columns = 2;
    ent->field_count = 4;
    strcpy(ent->fields[0].name, "name"); strcpy(ent->fields[0].label, "Name");
    ent->fields[0].type = BMW_FIELD_TEXT; ent->fields[0].required = true;
    strcpy(ent->fields[1].name, "email"); strcpy(ent->fields[1].label, "Email");
    ent->fields[1].type = BMW_FIELD_EMAIL; ent->fields[1].required = true;
    strcpy(ent->fields[2].name, "phone"); strcpy(ent->fields[2].label, "Phone");
    ent->fields[2].type = BMW_FIELD_TEXT;
    strcpy(ent->fields[3].name, "notes"); strcpy(ent->fields[3].label, "Notes");
    ent->fields[3].type = BMW_FIELD_TEXTAREA;
    ctx->entity_count = 1;

    /* Get HMAC key from auth service if available */
    bmw_auth_ctx_t *auth = (bmw_auth_ctx_t *)bmw_registry_get(services, "auth.ctx");
    if (auth) g_hmac_key = auth->hmac_key;

    /* Register routes */
    bmw_router_t *router = (bmw_router_t *)bmw_registry_get(services, "http.router");
    if (router) {
        bmw_router_add(router, "/api/_meta", BMW_HTTP_GET, meta_list_all, ctx, false);
        bmw_router_add(router, "/api/metadata/", BMW_HTTP_GET, meta_schema_handler, ctx, true);
        bmw_router_add(router, "/api/_binary/", BMW_HTTP_GET, meta_binary_handler, ctx, true);
        bmw_router_add(router, "/api/", BMW_HTTP_UNKNOWN, meta_api_handler, ctx, true);
        bmw_router_add(router, "/bmw/routes", BMW_HTTP_GET, meta_routes, ctx, false);
        bmw_router_add(router, "/bmw/protocol", BMW_HTTP_GET, meta_protocol, ctx, false);
    }

    /* Register metadata service */
    bmw_registry_register(services, "meta.ctx", ctx);

    return 0;
}

static void meta_shutdown_fn(bmw_module_t *self) {
    if (self->ctx) { free(self->ctx); self->ctx = NULL; }
}

static bmw_module_t meta_module = {
    .name = "meta",
    .priority = 15,
    .init = meta_init,
    .start = NULL,
    .stop = NULL,
    .shutdown = meta_shutdown_fn,
    .on_fd_ready = NULL,
    .handle_request = NULL,
    .on_tick = NULL,
    .ctx = NULL
};

bmw_module_t *bmw_meta_module_create(void) {
    return &meta_module;
}
