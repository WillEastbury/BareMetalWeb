/*
 * Static file server - serves files from a root directory with path confinement
 */
#include "bmw_http.h"
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#endif

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

    /* Open file FIRST to obtain a handle, then verify the resolved path of the open
     * handle is under root_dir. This closes the TOCTOU window between canonicalize
     * and fopen (symlink swap). */
    FILE *f = NULL;
    {
#ifdef _WIN32
        f = fopen(fullpath, "rb");
        if (!f) {
            bmw_response_set_status(resp, 404);
            bmw_response_set_body(resp, "Not Found", 9);
            return -1;
        }
        HANDLE h = (HANDLE)_get_osfhandle(_fileno(f));
        char resolved[1024];
        DWORD rn = GetFinalPathNameByHandleA(h, resolved, sizeof(resolved), FILE_NAME_NORMALIZED);
        if (rn == 0 || rn >= sizeof(resolved)) { fclose(f); bmw_response_set_status(resp, 500); return -1; }
        char resolved_root[1024];
        if (!_fullpath(resolved_root, root_dir, sizeof(resolved_root))) {
            fclose(f); bmw_response_set_status(resp, 500); return -1;
        }
        /* Strip \\?\ prefix if present */
        const char *rcmp = resolved;
        if (strncmp(rcmp, "\\\\?\\", 4) == 0) rcmp += 4;
        size_t rlen = strlen(resolved_root);
        if (_strnicmp(rcmp, resolved_root, rlen) != 0 ||
            (rcmp[rlen] != '\0' && rcmp[rlen] != '\\')) {
            fclose(f);
            bmw_response_set_status(resp, 403);
            bmw_response_set_body(resp, "Forbidden", 9);
            return -1;
        }
#else
        int fd = open(fullpath, O_RDONLY | O_NOFOLLOW
#ifdef O_CLOEXEC
                                | O_CLOEXEC
#endif
                     );
        if (fd < 0) {
            bmw_response_set_status(resp, 404);
            bmw_response_set_body(resp, "Not Found", 9);
            return -1;
        }
        struct stat st;
        if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
            close(fd); bmw_response_set_status(resp, 403);
            bmw_response_set_body(resp, "Forbidden", 9); return -1;
        }
        /* Verify the path still resolves under root (defence-in-depth; O_NOFOLLOW
         * already prevents the final-component symlink swap). */
        char *resolved = realpath(fullpath, NULL);
        char *resolved_root = realpath(root_dir, NULL);
        if (!resolved || !resolved_root) {
            free(resolved); free(resolved_root); close(fd);
            bmw_response_set_status(resp, 500); return -1;
        }
        size_t rlen = strlen(resolved_root);
        if (strncmp(resolved, resolved_root, rlen) != 0 ||
            (resolved[rlen] != '\0' && resolved[rlen] != '/')) {
            free(resolved); free(resolved_root); close(fd);
            bmw_response_set_status(resp, 403);
            bmw_response_set_body(resp, "Forbidden", 9); return -1;
        }
        free(resolved); free(resolved_root);
        f = fdopen(fd, "rb");
        if (!f) { close(fd); bmw_response_set_status(resp, 500); return -1; }
#endif
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
    /* Transfer ownership of content buffer directly — avoid second malloc+copy */
    if (resp->body) free(resp->body);
    resp->body = content;
    resp->body_len = (size_t)fsize;
    resp->body_cap = (size_t)fsize;
    return 0;
}
