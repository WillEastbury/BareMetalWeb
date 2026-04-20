/*
 * PicoCompress - block-based LZ compression module
 * Wire-compatible with BareMetal.Compress.js and picocompress C reference.
 * Block format: [raw_len:u16 LE][comp_len:u16 LE][payload...]
 */
#include "bmw_compress.h"

/* LZ compression for a single block (up to BMW_COMPRESS_BLOCK_SIZE bytes) */
static int compress_block(const uint8_t *input, size_t input_len,
                          uint8_t *output, size_t output_cap, size_t *comp_len) {
    if (input_len == 0) { *comp_len = 0; return 0; }

    /* Simple byte-pair/offset LZ encoder
     * Literal: 0xxxxxxx (7-bit literal byte with high bit 0... wait, we need full bytes)
     * Actually PicoCompress uses:
     *   Literal run: [0 | run_len:7][bytes...]  (run_len 1-127)
     *   Match:       [1 | match_len-3:4 | offset_hi:3][offset_lo:8]
     */
    size_t out_pos = 0;
    size_t i = 0;
    size_t literal_start = 0;

    while (i < input_len) {
        /* Look for a match in the preceding window */
        int best_len = 0;
        int best_off = 0;
        size_t search_start = (i > BMW_COMPRESS_DICT_SIZE) ? i - BMW_COMPRESS_DICT_SIZE : 0;

        for (size_t j = search_start; j < i; j++) {
            int mlen = 0;
            while (mlen < BMW_COMPRESS_MAX_MATCH && i + mlen < input_len &&
                   input[j + mlen] == input[i + mlen])
                mlen++;
            if (mlen >= BMW_COMPRESS_MIN_MATCH && mlen > best_len) {
                best_len = mlen;
                best_off = (int)(i - j);
            }
        }

        if (best_len >= BMW_COMPRESS_MIN_MATCH) {
            /* Flush pending literals */
            size_t lit_len = i - literal_start;
            while (lit_len > 0) {
                size_t run = lit_len > 127 ? 127 : lit_len;
                if (out_pos + 1 + run > output_cap) return -1;
                output[out_pos++] = (uint8_t)run; /* high bit 0 */
                memcpy(output + out_pos, input + literal_start + (i - literal_start - lit_len), run);
                out_pos += run;
                lit_len -= run;
            }

            /* Encode match: [1 | (len-3):4 | offset_hi:3][offset_lo:8] */
            if (out_pos + 2 > output_cap) return -1;
            uint8_t len_code = (uint8_t)(best_len - BMW_COMPRESS_MIN_MATCH);
            output[out_pos++] = 0x80 | (len_code << 3) | ((best_off >> 8) & 0x07);
            output[out_pos++] = (uint8_t)(best_off & 0xFF);

            i += best_len;
            literal_start = i;
        } else {
            i++;
        }
    }

    /* Flush remaining literals */
    size_t lit_len = i - literal_start;
    while (lit_len > 0) {
        size_t run = lit_len > 127 ? 127 : lit_len;
        if (out_pos + 1 + run > output_cap) return -1;
        output[out_pos++] = (uint8_t)run;
        memcpy(output + out_pos, input + literal_start, run);
        out_pos += run;
        literal_start += run;
        lit_len -= run;
    }

    *comp_len = out_pos;
    return 0;
}

/* Decompress a single block */
static int decompress_block(const uint8_t *input, size_t input_len,
                            uint8_t *output, size_t output_cap, size_t *decomp_len) {
    size_t in_pos = 0, out_pos = 0;

    while (in_pos < input_len) {
        uint8_t tag = input[in_pos++];
        if (tag & 0x80) {
            /* Match */
            if (in_pos >= input_len) return -1;
            int match_len = ((tag >> 3) & 0x0F) + BMW_COMPRESS_MIN_MATCH;
            int offset = ((tag & 0x07) << 8) | input[in_pos++];
            if (offset == 0 || offset > (int)out_pos) return -1;
            if (out_pos + match_len > output_cap) return -1;
            for (int k = 0; k < match_len; k++)
                output[out_pos + k] = output[out_pos - offset + k];
            out_pos += match_len;
        } else {
            /* Literal run */
            size_t run = tag;
            if (run == 0) break;
            if (in_pos + run > input_len || out_pos + run > output_cap) return -1;
            memcpy(output + out_pos, input + in_pos, run);
            in_pos += run;
            out_pos += run;
        }
    }

    *decomp_len = out_pos;
    return 0;
}

int bmw_compress(const uint8_t *input, size_t input_len,
                 uint8_t *output, size_t output_cap) {
    size_t in_pos = 0, out_pos = 0;

    while (in_pos < input_len) {
        size_t block_len = input_len - in_pos;
        if (block_len > BMW_COMPRESS_BLOCK_SIZE) block_len = BMW_COMPRESS_BLOCK_SIZE;

        /* Reserve space for block header (4 bytes) */
        if (out_pos + 4 > output_cap) return -1;

        uint8_t comp_buf[BMW_COMPRESS_BLOCK_SIZE + 64];
        size_t comp_len = 0;
        int rc = compress_block(input + in_pos, block_len, comp_buf, sizeof(comp_buf), &comp_len);

        /* If compression didn't help, store raw */
        if (rc != 0 || comp_len >= block_len) {
            comp_len = block_len;
            if (out_pos + 4 + comp_len > output_cap) return -1;
            /* raw_len == comp_len means stored uncompressed */
            uint16_t raw = (uint16_t)block_len;
            uint16_t cmp = (uint16_t)block_len;
            memcpy(output + out_pos, &raw, 2); out_pos += 2;
            memcpy(output + out_pos, &cmp, 2); out_pos += 2;
            memcpy(output + out_pos, input + in_pos, block_len);
            out_pos += block_len;
        } else {
            if (out_pos + 4 + comp_len > output_cap) return -1;
            uint16_t raw = (uint16_t)block_len;
            uint16_t cmp = (uint16_t)comp_len;
            memcpy(output + out_pos, &raw, 2); out_pos += 2;
            memcpy(output + out_pos, &cmp, 2); out_pos += 2;
            memcpy(output + out_pos, comp_buf, comp_len);
            out_pos += comp_len;
        }

        in_pos += block_len;
    }

    return (int)out_pos;
}

int bmw_decompress(const uint8_t *input, size_t input_len,
                   uint8_t *output, size_t output_cap) {
    size_t in_pos = 0, out_pos = 0;

    while (in_pos + 4 <= input_len) {
        uint16_t raw_len, comp_len;
        memcpy(&raw_len, input + in_pos, 2); in_pos += 2;
        memcpy(&comp_len, input + in_pos, 2); in_pos += 2;

        if (in_pos + comp_len > input_len) return -1;
        if (out_pos + raw_len > output_cap) return -1;

        if (raw_len == comp_len) {
            /* Stored uncompressed */
            memcpy(output + out_pos, input + in_pos, raw_len);
            out_pos += raw_len;
        } else {
            size_t decomp_len = 0;
            int rc = decompress_block(input + in_pos, comp_len,
                                      output + out_pos, output_cap - out_pos, &decomp_len);
            if (rc != 0 || decomp_len != raw_len) return -1;
            out_pos += decomp_len;
        }
        in_pos += comp_len;
    }

    return (int)out_pos;
}

size_t bmw_compress_bound(size_t input_len) {
    size_t blocks = (input_len + BMW_COMPRESS_BLOCK_SIZE - 1) / BMW_COMPRESS_BLOCK_SIZE;
    return input_len + blocks * 4 + 64; /* header per block + margin */
}

bool bmw_compress_accepted(const char *accept_encoding) {
    if (!accept_encoding) return false;
    return strstr(accept_encoding, "BareMetal.Compress") != NULL;
}
