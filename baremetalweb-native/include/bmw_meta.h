#ifndef BMW_META_H
#define BMW_META_H

#include "bmw_module.h"

/*
 * Metadata & Entity API Module
 * Serves entity schemas, CRUD endpoints, BSO1 binary responses, and WebSocket frames.
 *
 * Endpoints:
 *   /api/_meta                         - list all entity metadata
 *   /api/metadata/{slug}               - get entity schema JSON
 *   /api/_binary/{slug}/_schema        - entity schema in BSO1
 *   /api/_binary/{slug}/_layout        - entity layout in BSO1
 *   /api/_binary/{slug}                - list entities (BSO1 or JSON)
 *   /api/_binary/{slug}/{id}           - get/update/delete entity
 *   /api/{slug}                        - JSON CRUD fallback
 *   /api/{slug}/{id}                   - JSON single entity
 *   /_binary/_key                      - HMAC signing key (public portion)
 *
 * Config:
 *   meta_dir   - directory containing entity .json schema files
 */

#define BMW_META_MAX_ENTITIES  16
#define BMW_META_MAX_FIELDS    32
#define BMW_META_MAX_RECORDS   64
#define BMW_META_FIELD_SIZE    64
#define BMW_META_VALUE_SIZE    128

/* Field types matching BareMetal.Metadata normalisation */
typedef enum {
    BMW_FIELD_TEXT = 0,
    BMW_FIELD_NUMBER,
    BMW_FIELD_EMAIL,
    BMW_FIELD_DATE,
    BMW_FIELD_DATETIME,
    BMW_FIELD_BOOL,
    BMW_FIELD_SELECT,
    BMW_FIELD_TEXTAREA,
    BMW_FIELD_HIDDEN,
    BMW_FIELD_LOOKUP
} bmw_field_type_t;

typedef struct {
    char name[BMW_META_FIELD_SIZE];
    char label[BMW_META_FIELD_SIZE];
    bmw_field_type_t type;
    bool required;
    char lookup_url[128];
} bmw_field_def_t;

typedef struct {
    char name[BMW_META_FIELD_SIZE];
    char slug[BMW_META_FIELD_SIZE];
    char endpoint[128];
    bmw_field_def_t fields[BMW_META_MAX_FIELDS];
    int field_count;
    int columns; /* layout columns */
} bmw_entity_def_t;

/* In-memory record store (WAL-backed) */
typedef struct {
    uint32_t id;
    char values[BMW_META_MAX_FIELDS][BMW_META_VALUE_SIZE];
    bool active;
} bmw_record_t;

typedef struct {
    bmw_entity_def_t entities[BMW_META_MAX_ENTITIES];
    int entity_count;
    /* Simple in-memory store per entity */
    bmw_record_t records[BMW_META_MAX_ENTITIES][BMW_META_MAX_RECORDS];
    int record_counts[BMW_META_MAX_ENTITIES];
    uint32_t next_id[BMW_META_MAX_ENTITIES];
} bmw_meta_ctx_t;

bmw_module_t *bmw_meta_module_create(void);

/* BSO1 serialization helpers */
#define BSO1_MAGIC      0x314F5342  /* "BSO1" LE */
#define BSO1_VERSION    3
#define BSO1_HEADER_LEN 40  /* 4 magic + 1 ver + 1 schemaVer + 2 reserved + 32 hmac */

int bmw_bso1_encode_list(bmw_meta_ctx_t *ctx, int entity_idx,
                         uint8_t *out, size_t out_cap, size_t *out_len,
                         const uint8_t *hmac_key);

int bmw_bso1_encode_record(bmw_meta_ctx_t *ctx, int entity_idx, int record_idx,
                           uint8_t *out, size_t out_cap, size_t *out_len,
                           const uint8_t *hmac_key);

#endif /* BMW_META_H */
