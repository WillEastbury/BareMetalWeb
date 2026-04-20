#ifndef BMW_COMPRESS_H
#define BMW_COMPRESS_H

#include "bmw_platform.h"

/*
 * PicoCompress - block-based LZ compression
 * Byte-identical to picocompress C reference and BareMetal.Compress.js
 *
 * Block format: [raw_len:uint16 LE][comp_len:uint16 LE][payload...]
 * Block size: 508 bytes (default)
 * HTTP: Content-Encoding: BareMetal.Compress / Accept-Encoding: BareMetal.Compress
 */

#define BMW_COMPRESS_BLOCK_SIZE 508
#define BMW_COMPRESS_DICT_SIZE  256
#define BMW_COMPRESS_MIN_MATCH  3
#define BMW_COMPRESS_MAX_MATCH  18

/* Compress a buffer into blocks. Returns total output size, or -1 on error. */
int bmw_compress(const uint8_t *input, size_t input_len,
                 uint8_t *output, size_t output_cap);

/* Decompress block-encoded data. Returns decompressed size, or -1 on error. */
int bmw_decompress(const uint8_t *input, size_t input_len,
                   uint8_t *output, size_t output_cap);

/* Compute worst-case compressed size for a given input length */
size_t bmw_compress_bound(size_t input_len);

/* Check if request accepts BareMetal.Compress encoding */
bool bmw_compress_accepted(const char *accept_encoding);

#endif /* BMW_COMPRESS_H */
