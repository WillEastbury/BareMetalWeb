#ifndef BMW_EMBEDDED_FILES_H
#define BMW_EMBEDDED_FILES_H

#include <stdint.h>
#include <stddef.h>

typedef struct { const char *path; const uint8_t *data; size_t len; const char *mime; } embedded_file_t;

extern const embedded_file_t bmw_embedded_files[];
extern const size_t bmw_embedded_file_count;

#endif
