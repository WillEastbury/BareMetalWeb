cmake_minimum_required(VERSION 3.16)
project(baremetalweb_native C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Platform detection
if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0601 -DWIN32_LEAN_AND_MEAN -D_CRT_SECURE_NO_WARNINGS)
    set(PLATFORM_LIBS ws2_32)
else()
    set(PLATFORM_LIBS)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_definitions(-DBMW_USE_EPOLL)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
        add_definitions(-DBMW_USE_KQUEUE)
    endif()
endif()

# Sources
set(CORE_SOURCES
    src/core/event_loop.c
    src/core/module.c
    src/core/buffer_pool.c
)

set(HTTP_SOURCES
    src/mod_http/http_server.c
    src/mod_http/http_parser.c
    src/mod_http/http_router.c
    src/mod_http/http_template.c
    src/mod_http/http_static.c
)

set(WAL_SOURCES
    src/mod_wal/wal_engine.c
    src/mod_wal/wal_tcp.c
    src/mod_wal/wal_module.c
)

set(AUTH_SOURCES
    src/mod_auth/auth_oidc.c
)

set(META_SOURCES
    src/mod_meta/meta_module.c
)

set(COMPRESS_SOURCES
    src/mod_compress/compress.c
)

set(WS_SOURCES
    src/mod_ws/ws_module.c
)

add_executable(baremetalweb
    src/main.c
    ${CORE_SOURCES}
    ${HTTP_SOURCES}
    ${WAL_SOURCES}
    ${AUTH_SOURCES}
    ${META_SOURCES}
    ${COMPRESS_SOURCES}
    ${WS_SOURCES}
)

target_include_directories(baremetalweb PRIVATE include src)
target_link_libraries(baremetalweb PRIVATE ${PLATFORM_LIBS})

# Compiler warnings
if(MSVC)
    target_compile_options(baremetalweb PRIVATE /W4)
else()
    target_compile_options(baremetalweb PRIVATE -Wall -Wextra -Wpedantic)
endif()
