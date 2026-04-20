/*
 * Pre-allocated buffer pool for zero-alloc hot path
 */
#include "bmw_platform.h"

#define BMW_POOL_BLOCK_SIZE  512
#define BMW_POOL_BLOCK_COUNT 32

typedef struct {
    uint8_t blocks[BMW_POOL_BLOCK_COUNT][BMW_POOL_BLOCK_SIZE];
    uint32_t bitmap[BMW_POOL_BLOCK_COUNT / 32]; /* bit set = in use */
} bmw_buffer_pool_t;

static bmw_buffer_pool_t g_pool;

void bmw_pool_init(void) {
    memset(&g_pool, 0, sizeof(g_pool));
}

void *bmw_pool_alloc(void) {
    for (int i = 0; i < BMW_POOL_BLOCK_COUNT / 32; i++) {
        if (g_pool.bitmap[i] != 0xFFFFFFFF) {
            for (int bit = 0; bit < 32; bit++) {
                if (!(g_pool.bitmap[i] & (1u << bit))) {
                    g_pool.bitmap[i] |= (1u << bit);
                    int idx = i * 32 + bit;
                    memset(g_pool.blocks[idx], 0, BMW_POOL_BLOCK_SIZE);
                    return g_pool.blocks[idx];
                }
            }
        }
    }
    return NULL; /* pool exhausted */
}

void bmw_pool_free(void *ptr) {
    if (!ptr) return;
    ptrdiff_t offset = (uint8_t *)ptr - (uint8_t *)g_pool.blocks;
    if (offset < 0 || offset >= (ptrdiff_t)sizeof(g_pool.blocks)) return;
    int idx = (int)(offset / BMW_POOL_BLOCK_SIZE);
    g_pool.bitmap[idx / 32] &= ~(1u << (idx % 32));
}

size_t bmw_pool_block_size(void) {
    return BMW_POOL_BLOCK_SIZE;
}
