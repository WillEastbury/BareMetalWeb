#ifndef BMW_PLATFORM_H
#define BMW_PLATFORM_H

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    typedef SOCKET bmw_socket_t;
    #define BMW_INVALID_SOCKET INVALID_SOCKET
    #define BMW_SOCKET_ERROR SOCKET_ERROR
    #define bmw_close_socket closesocket
    #define bmw_socket_errno WSAGetLastError()
    #define BMW_EWOULDBLOCK WSAEWOULDBLOCK
    #define BMW_EINPROGRESS WSAEINPROGRESS
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
    #include <poll.h>
    typedef int bmw_socket_t;
    #define BMW_INVALID_SOCKET (-1)
    #define BMW_SOCKET_ERROR (-1)
    #define bmw_close_socket close
    #define bmw_socket_errno errno
    #define BMW_EWOULDBLOCK EWOULDBLOCK
    #define BMW_EINPROGRESS EINPROGRESS
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static inline int bmw_set_nonblocking(bmw_socket_t sock) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif
}

static inline void bmw_platform_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
}

static inline void bmw_platform_shutdown(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

#endif /* BMW_PLATFORM_H */
