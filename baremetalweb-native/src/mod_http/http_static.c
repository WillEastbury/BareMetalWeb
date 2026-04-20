/*
 * Static file server - serves files from a root directory with path confinement
 */
#include "bmw_http.h"

static const char *get_mime_type(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return "application/octet-stream";
    ext++;
    if (strcmp(ext, "html") == 0 || strcmp(ext, "htm") == 0) return "text/html";
    if (strcmp(ext, "css") == 0)  return "text/css";
    if (strcmp(ext, "js") == 0)   return "application/javascript";
    if (strcmp(ext, "json") == 0) return "application/json";
    if (strcmp(ext, "png") == 0)  return "image/png";
    if (strcmp(ext, "jpg") == 0 || strcmp(ext, "jpeg") == 0) return "image/jpeg";
    if (strcmp(ext, "gif") == 0)  return "image/gif";
    if (strcmp(ext, "svg") == 0)  return "image/svg+xml";
    if (strcmp(ext, "ico") == 0)  return "image/x-icon";
    if (strcmp(ext, "txt") == 0)  return "text/plain";
    if (strcmp(ext, "xml") == 0)  return "application/xml";
    if (strcmp(ext, "woff") == 0) return "font/woff";
    if (strcmp(ext, "woff2") == 0) return "font/woff2";
    return "application/octet-stream";
}

int bmw_static_serve(const char *root_dir, const char *path, bmw_response_t *resp) {
    /* Reject traversal attempts */
    if (strstr(path, "..") || strstr(path, "//")) {
        bmw_response_set_status(resp, 403);
        bmw_response_set_body(resp, "Forbidden", 9);
        return -1;
    }

    /* Build full path */
    char fullpath[1024];
    int n = snprintf(fullpath, sizeof(fullpath), "%s%s%s",
                     root_dir,
                     (path[0] == '/') ? "" : "/",
                     path);
    if (n < 0 || (size_t)n >= sizeof(fullpath)) {
        bmw_response_set_status(resp, 414);
        return -1;
    }

    /* Normalize separators on Windows */
#ifdef _WIN32
    for (char *c = fullpath; *c; c++) {
        if (*c == '/') *c = '\\';
    }
#endif

    /* Canonicalize and verify the resolved path stays under root_dir */
    {
#ifdef _WIN32
        char resolved[1024];
        if (!_fullpath(resolved, fullpath, sizeof(resolved))) {
            bmw_response_set_status(resp, 404);
            bmw_response_set_body(resp, "Not Found", 9);
            return -1;
        }
        /* Verify prefix match against root_dir */
        char resolved_root[1024];
        if (!_fullpath(resolved_root, root_dir, sizeof(resolved_root))) {
            bmw_response_set_status(resp, 500);
            return -1;
        }
        size_t rlen = strlen(resolved_root);
        if (strncmp(resolved, resolved_root, rlen) != 0) {
            bmw_response_set_status(resp, 403);
            bmw_response_set_body(resp, "Forbidden", 9);
            return -1;
        }
        snprintf(fullpath, sizeof(fullpath), "%s", resolved);
#else
        char *resolved = realpath(fullpath, NULL);
        if (!resolved) {
            bmw_response_set_status(resp, 404);
            bmw_response_set_body(resp, "Not Found", 9);
            return -1;
        }
        char *resolved_root = realpath(root_dir, NULL);
        if (!resolved_root) { free(resolved); bmw_response_set_status(resp, 500); return -1; }
        size_t rlen = strlen(resolved_root);
        if (strncmp(resolved, resolved_root, rlen) != 0) {
            free(resolved); free(resolved_root);
            bmw_response_set_status(resp, 403);
            bmw_response_set_body(resp, "Forbidden", 9);
            return -1;
        }
        snprintf(fullpath, sizeof(fullpath), "%s", resolved);
        free(resolved); free(resolved_root);
#endif
    }

    /* Open and read file */
    FILE *f = fopen(fullpath, "rb");
    if (!f) {
        bmw_response_set_status(resp, 404);
        bmw_response_set_body(resp, "Not Found", 9);
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    /* Validate ftell result */
    if (fsize < 0) {
        fclose(f);
        bmw_response_set_status(resp, 500);
        return -1;
    }

    /* Limit file size to 10MB */
    if (fsize > 10 * 1024 * 1024) {
        fclose(f);
        bmw_response_set_status(resp, 413);
        bmw_response_set_body(resp, "File Too Large", 14);
        return -1;
    }

    char *content = malloc((size_t)fsize);
    if (!content) {
        fclose(f);
        bmw_response_set_status(resp, 500);
        return -1;
    }

    size_t bytes_read = fread(content, 1, (size_t)fsize, f);
    fclose(f);

    if (bytes_read != (size_t)fsize) {
        free(content);
        bmw_response_set_status(resp, 500);
        return -1;
    }

    bmw_response_set_status(resp, 200);
    bmw_response_add_header(resp, "Content-Type", get_mime_type(path));
    bmw_response_set_body(resp, content, (size_t)fsize);
    free(content);
    return 0;
}
