#ifndef BMW_WAL_H
#define BMW_WAL_H

#include "bmw_module.h"

/*
 * WAL Engine - PicoWAL protocol implementation
 * Based on the PicoWAL wire format and data structures.
 */

#define WAL_SLOT_SIZE       256
#define WAL_SLOT_COUNT      16
#define WAL_INDEX_SIZE      16
#define WAL_RING_SIZE       8

/* WAL operations */
typedef enum {
    WAL_OP_SET    = 0x01,
    WAL_OP_DELETE = 0x02,
    WAL_OP_MERGE  = 0x03
} wal_op_t;

/*
 * WAL keys are NOT hashes. They are 32-bit packed identifiers:
 *   bits [31..22]  pack  (10 bits, 0..1023)  — namespace / table
 *   bits [21..0]   id    (22 bits, 0..4194303) — record id within pack
 * Pack/id are assigned by the caller, never derived from arbitrary strings,
 * so identity is collision-free by construction (each (pack,id) pair is unique).
 */
#define WAL_KEY_PACK_BITS   10
#define WAL_KEY_ID_BITS     22
#define WAL_KEY_PACK_MAX    ((1u << WAL_KEY_PACK_BITS) - 1u)   /* 1023 */
#define WAL_KEY_ID_MAX      ((1u << WAL_KEY_ID_BITS) - 1u)     /* 4194303 */

static inline uint32_t bmw_wal_make_key(uint16_t pack, uint32_t id) {
    return ((uint32_t)(pack & WAL_KEY_PACK_MAX) << WAL_KEY_ID_BITS)
         | (id & WAL_KEY_ID_MAX);
}
static inline uint16_t bmw_wal_key_pack(uint32_t key) {
    return (uint16_t)((key >> WAL_KEY_ID_BITS) & WAL_KEY_PACK_MAX);
}
static inline uint32_t bmw_wal_key_id(uint32_t key) {
    return key & WAL_KEY_ID_MAX;
}

/* Delta header: [key:u32 (pack|id)][value_len:u16][op:u8][reserved:u8] */
#pragma pack(push, 1)
typedef struct {
    uint32_t key;
    uint16_t value_len;
    uint8_t  op;
    uint8_t  reserved;
} wal_delta_header_t;
#pragma pack(pop)

/* WAL index entry */
typedef struct {
    uint32_t seq;
    uint32_t key;
    uint8_t  slot;
    uint16_t len;
    uint8_t  flags;
} wal_entry_t;

/* Request/response ring entries */
typedef struct {
    volatile uint8_t ready;
    uint8_t  op;
    uint8_t  slot;
    uint16_t len;
    uint32_t key;
} wal_request_t;

typedef struct {
    volatile uint8_t ready;
    uint8_t  status;
    uint8_t  result_slot;
    uint16_t result_len;
    uint32_t seq;
    uint32_t delta_count;
} wal_response_t;

/* WAL state */
typedef struct {
    uint8_t       slots[WAL_SLOT_COUNT][WAL_SLOT_SIZE];
    wal_entry_t   index[WAL_INDEX_SIZE];
    int           index_count;
    uint32_t      next_seq;

    wal_request_t  req_ring[WAL_RING_SIZE];
    wal_response_t resp_ring[WAL_RING_SIZE];
    int            req_head;
    int            req_tail;
    int            resp_head;
    int            resp_tail;

    /* Slot allocation bitmap */
    uint32_t      slot_bitmap; /* bit set = slot in use */
} wal_state_t;

/* WAL Engine API (internal service interface) */
typedef struct {
    wal_state_t state;

    /* Append a value for a key (key = pack<<22 | id) */
    int (*append)(void *engine, uint32_t key, const uint8_t *value,
                  uint16_t value_len, wal_op_t op, uint32_t *out_seq);

    /* Read all deltas for a key */
    int (*read)(void *engine, uint32_t key, uint8_t *out_buf,
                size_t buf_cap, uint32_t *out_delta_count, uint16_t *out_total_len);

    /* Compact: merge duplicate keys, keep latest */
    int (*compact)(void *engine);
} wal_engine_t;

/* Initialize WAL engine */
int  wal_engine_init(wal_engine_t *engine);
void wal_engine_destroy(wal_engine_t *engine);

/* WAL TCP protocol opcodes (PicoWAL compatible) */
#define WAL_TCP_OP_NOOP   0x00
#define WAL_TCP_OP_APPEND 0x01
#define WAL_TCP_OP_READ   0x02

#define WAL_TCP_ACK_NOOP   0x80
#define WAL_TCP_ACK_APPEND 0x81
#define WAL_TCP_ACK_READ   0x82
#define WAL_TCP_ACK_ERROR  0xFF

#define WAL_TCP_ERR_FULL   0x01
#define WAL_TCP_ERR_TOOBIG 0x02
#define WAL_TCP_ERR_PROTO  0x03

/* WAL module (exposes wal_engine_t as a service + optional TCP listener) */
bmw_module_t *bmw_wal_module_create(void);

/* WAL key utility (legacy hash kept only for migration; do not use for new code) */
uint32_t bmw_wal_hash(const char *key, size_t len);

#endif /* BMW_WAL_H */
