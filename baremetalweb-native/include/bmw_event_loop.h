#ifndef BMW_EVENT_LOOP_H
#define BMW_EVENT_LOOP_H

#include "bmw_platform.h"

#define BMW_EVENT_READ  0x01
#define BMW_EVENT_WRITE 0x02
#define BMW_MAX_FDS     32

typedef void (*bmw_fd_callback_t)(bmw_socket_t fd, int events, void *userdata);

typedef struct {
    bmw_socket_t fd;
    int events;
    bmw_fd_callback_t callback;
    void *userdata;
    bool active;
} bmw_fd_entry_t;

typedef struct bmw_event_loop {
    bmw_fd_entry_t fds[BMW_MAX_FDS];
    int fd_count;
    bool running;

#ifdef BMW_USE_EPOLL
    int epoll_fd;
#elif defined(BMW_USE_KQUEUE)
    int kqueue_fd;
#endif
} bmw_event_loop_t;

int  bmw_loop_init(bmw_event_loop_t *loop);
int  bmw_loop_add_fd(bmw_event_loop_t *loop, bmw_socket_t fd, int events,
                     bmw_fd_callback_t cb, void *userdata);
int  bmw_loop_mod_fd(bmw_event_loop_t *loop, bmw_socket_t fd, int events);
void bmw_loop_remove_fd(bmw_event_loop_t *loop, bmw_socket_t fd);
int  bmw_loop_run(bmw_event_loop_t *loop);
void bmw_loop_stop(bmw_event_loop_t *loop);
void bmw_loop_destroy(bmw_event_loop_t *loop);

#endif /* BMW_EVENT_LOOP_H */
