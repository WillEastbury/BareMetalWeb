import os

wwwroot = os.path.join(os.path.dirname(__file__), '..', 'wwwroot')
outdir = os.path.join(os.path.dirname(__file__), 'embedded')
os.makedirs(outdir, exist_ok=True)

files = sorted(f for f in os.listdir(wwwroot) if os.path.isfile(os.path.join(wwwroot, f)))

mime_map = {'.html':'text/html','.css':'text/css','.js':'application/javascript',
            '.json':'application/json','.png':'image/png','.ico':'image/x-icon'}

hdr = '#ifndef BMW_EMBEDDED_FILES_H\n#define BMW_EMBEDDED_FILES_H\n\n#include <stdint.h>\n#include <stddef.h>\n\ntypedef struct { const char *path; const uint8_t *data; size_t len; const char *mime; } embedded_file_t;\n\nextern const embedded_file_t bmw_embedded_files[];\nextern const size_t bmw_embedded_file_count;\n\n#endif\n'

src = '#include "bmw_embedded_files.h"\n\n'
table_entries = []
count = 0

for name in files:
    path = os.path.join(wwwroot, name)
    data = open(path, 'rb').read()
    varname = 'file_' + name.replace('.','_').replace('-','_')
    ext = os.path.splitext(name)[1]
    mime = mime_map.get(ext, 'application/octet-stream')
    
    src += f'static const uint8_t {varname}[] = {{\n'
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        src += '    ' + ','.join(f'0x{b:02x}' for b in chunk) + ',\n'
    src += f'}};\n\n'
    
    table_entries.append(f'    {{"/{name}", {varname}, {len(data)}, "{mime}"}}')
    count += 1

# Map / to index.html
table_entries.append(f'    {{"/", file_index_html, sizeof(file_index_html), "text/html"}}')
count += 1

src += 'const embedded_file_t bmw_embedded_files[] = {\n'
src += ',\n'.join(table_entries) + '\n};\n\n'
src += f'const size_t bmw_embedded_file_count = {count};\n'

with open(os.path.join(outdir, 'bmw_embedded_files.h'), 'w') as f:
    f.write(hdr)
with open(os.path.join(outdir, 'bmw_embedded_files.c'), 'w') as f:
    f.write(src)

total = sum(os.path.getsize(os.path.join(wwwroot, fn)) for fn in files)
print(f'Embedded {count-1} files, {total} bytes total into flash arrays')
