/*
 * Template engine - {{token}} substitution with HTML escaping
 */
#include "bmw_http.h"

static size_t html_escape(const char *src, size_t src_len, char *dst, size_t dst_cap) {
    size_t written = 0;
    for (size_t i = 0; i < src_len && written < dst_cap - 6; i++) {
        switch (src[i]) {
            case '&':  memcpy(dst + written, "&amp;", 5); written += 5; break;
            case '<':  memcpy(dst + written, "&lt;", 4); written += 4; break;
            case '>':  memcpy(dst + written, "&gt;", 4); written += 4; break;
            case '"':  memcpy(dst + written, "&quot;", 6); written += 6; break;
            case '\'': memcpy(dst + written, "&#39;", 5); written += 5; break;
            default:   dst[written++] = src[i]; break;
        }
    }
    return written;
}

int bmw_template_render(const char *tmpl, size_t tmpl_len,
                        bmw_template_var_t *vars, int var_count,
                        char *output, size_t output_cap, size_t *output_len) {
    size_t out_pos = 0;
    size_t i = 0;

    while (i < tmpl_len && out_pos < output_cap - 1) {
        /* Look for {{ */
        if (i + 1 < tmpl_len && tmpl[i] == '{' && tmpl[i+1] == '{') {
            /* Find closing }} */
            const char *close = NULL;
            for (size_t j = i + 2; j + 1 < tmpl_len; j++) {
                if (tmpl[j] == '}' && tmpl[j+1] == '}') {
                    close = &tmpl[j];
                    break;
                }
            }
            if (!close) {
                output[out_pos++] = tmpl[i++];
                continue;
            }

            /* Extract key */
            const char *key_start = &tmpl[i + 2];
            size_t key_len = (size_t)(close - key_start);

            /* Skip whitespace */
            while (key_len > 0 && *key_start == ' ') { key_start++; key_len--; }
            while (key_len > 0 && key_start[key_len - 1] == ' ') key_len--;

            /* Check for raw prefix (triple braces {{{key}}}) */
            bool raw = false;
            if (i + 2 < tmpl_len && tmpl[i+2] == '{' && close > key_start && *(close-1) == '}') {
                raw = true;
                key_start++;
                key_len -= 2;
            }

            /* Look up variable */
            const char *value = NULL;
            size_t value_len = 0;
            for (int v = 0; v < var_count; v++) {
                if (strlen(vars[v].key) == key_len && memcmp(vars[v].key, key_start, key_len) == 0) {
                    value = vars[v].value;
                    value_len = strlen(value);
                    break;
                }
            }

            if (value) {
                if (raw) {
                    size_t copy = value_len;
                    if (out_pos + copy >= output_cap) copy = output_cap - out_pos - 1;
                    memcpy(output + out_pos, value, copy);
                    out_pos += copy;
                } else {
                    out_pos += html_escape(value, value_len, output + out_pos, output_cap - out_pos);
                }
            }

            i = (size_t)(close - tmpl) + 2;
        } else {
            output[out_pos++] = tmpl[i++];
        }
    }

    output[out_pos] = '\0';
    if (output_len) *output_len = out_pos;
    return 0;
}
