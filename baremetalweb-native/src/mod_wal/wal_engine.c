/*
 * WAL Engine - PicoWAL-compatible Write-Ahead Log
 * Implements append, read, and compaction with slot-based storage.
 *
 * THREAD SAFETY: This engine is NOT thread-safe. All access must be serialized
 * to a single thread/core. On Pico 2W, confine WAL operations to Core 0 only.
 * If multi-core access is needed, add a spinlock or use the FIFO for cross-core RPC.
 */
#include "bmw_wal.h"

#ifdef BMW_PICO_BUILD
#include "pico/critical_section.h"
static critical_section_t wal_lock;
static bool wal_lock_init_done = false;
#define WAL_LOCK()   do { if (wal_lock_init_done) critical_section_enter_blocking(&wal_lock); } while(0)
#define WAL_UNLOCK() do { if (wal_lock_init_done) critical_section_exit(&wal_lock); } while(0)
#else
/* Desktop: single-threaded event loop, no lock needed */
#define WAL_LOCK()   ((void)0)
#define WAL_UNLOCK() ((void)0)
#endif

/* FNV-1a hash for key strings */
uint32_t bmw_wal_hash(const char *key, size_t len) {
    uint32_t h = 0x811c9dc5;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint8_t)key[i];
        h *= 0x01000193;
    }
    return h;
}

/* Allocate a slot from the pool */
static int slot_alloc(wal_state_t *state) {
    for (int i = 0; i < WAL_SLOT_COUNT; i++) {
        if (!(state->slot_bitmap & (1u << i))) {
            state->slot_bitmap |= (1u << i);
            return i;
        }
    }
    return -1; /* no free slots */
}

static void slot_free(wal_state_t *state, int slot) {
    if (slot >= 0 && slot < WAL_SLOT_COUNT)
        state->slot_bitmap &= ~(1u << slot);
}

/* Append a value for a key */
static int wal_append(void *engine_ptr, uint32_t key, const uint8_t *value,
                      uint16_t value_len, wal_op_t op, uint32_t *out_seq) {
    wal_engine_t *engine = (wal_engine_t *)engine_ptr;
    wal_state_t *state = &engine->state;

    WAL_LOCK();

    /* Check value fits in a slot (minus delta header) */
    if (value_len + sizeof(wal_delta_header_t) > WAL_SLOT_SIZE) {
        WAL_UNLOCK();
        return -2; /* too big */
    }

    if (state->index_count >= WAL_INDEX_SIZE) {
        WAL_UNLOCK();
        return -1; /* full, needs compaction */
    }

    int slot = slot_alloc(state);
    if (slot < 0) { WAL_UNLOCK(); return -1; }

    /* Write delta header + value into slot */
    wal_delta_header_t hdr = {
        .key = key,
        .value_len = value_len,
        .op = (uint8_t)op,
        .reserved = 0
    };
    memcpy(state->slots[slot], &hdr, sizeof(hdr));
    if (value_len > 0)
        memcpy(state->slots[slot] + sizeof(hdr), value, value_len);

    /* Add index entry */
    uint32_t seq = state->next_seq++;
    wal_entry_t *entry = &state->index[state->index_count++];
    entry->seq = seq;
    entry->key = key;
    entry->slot = (uint8_t)slot;
    entry->len = value_len + (uint16_t)sizeof(wal_delta_header_t);
    entry->flags = 0;

    if (out_seq) *out_seq = seq;
    WAL_UNLOCK();
    return 0;
}

/* Read all deltas for a key, concatenated into output buffer */
static int wal_read(void *engine_ptr, uint32_t key, uint8_t *out_buf,
                    size_t buf_cap, uint32_t *out_delta_count, uint16_t *out_total_len) {
    wal_engine_t *engine = (wal_engine_t *)engine_ptr;
    wal_state_t *state = &engine->state;

    WAL_LOCK();

    uint32_t count = 0;
    uint16_t total = 0;

    /* Collect matching entries sorted by seq (already in order) */
    for (int i = 0; i < state->index_count; i++) {
        if (state->index[i].key == key) {
            uint16_t len = state->index[i].len;
            if (total + len > (uint16_t)buf_cap) break;
            memcpy(out_buf + total, state->slots[state->index[i].slot], len);
            total += len;
            count++;
        }
    }

    if (out_delta_count) *out_delta_count = count;
    if (out_total_len) *out_total_len = total;
    WAL_UNLOCK();
    return (count > 0) ? 0 : -1; /* -1 = not found */
}

/* Compact: for each key, keep only the latest entry */
static int wal_compact(void *engine_ptr) {
    wal_engine_t *engine = (wal_engine_t *)engine_ptr;
    wal_state_t *state = &engine->state;

    WAL_LOCK();

    /* Mark older duplicates for removal */
    for (int i = 0; i < state->index_count; i++) {
        if (state->index[i].flags & 0x01) continue; /* already marked */
        for (int j = i + 1; j < state->index_count; j++) {
            if (state->index[j].key == state->index[i].key) {
                /* j is newer (higher seq), mark i for removal */
                state->index[i].flags |= 0x01;
                slot_free(state, state->index[i].slot);
                break;
            }
        }
    }

    /* Compact the index array */
    int write_idx = 0;
    for (int i = 0; i < state->index_count; i++) {
        if (!(state->index[i].flags & 0x01)) {
            if (write_idx != i)
                state->index[write_idx] = state->index[i];
            write_idx++;
        }
    }
    state->index_count = write_idx;
    WAL_UNLOCK();
    return 0;
}

int wal_engine_init(wal_engine_t *engine) {
    memset(engine, 0, sizeof(*engine));
    engine->append = wal_append;
    engine->read = wal_read;
    engine->compact = wal_compact;
    engine->state.next_seq = 1;
#ifdef BMW_PICO_BUILD
    if (!wal_lock_init_done) {
        critical_section_init(&wal_lock);
        wal_lock_init_done = true;
    }
#endif
    return 0;
}

void wal_engine_destroy(wal_engine_t *engine) {
    memset(engine, 0, sizeof(*engine));
}
