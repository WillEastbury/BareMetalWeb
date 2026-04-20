/*
 * Event loop - abstracted poller (epoll/kqueue/WSAPoll/select fallback)
 */
#include "bmw_event_loop.h"
#include "bmw_module.h"
#include <time.h>

#ifdef BMW_USE_EPOLL
#include <sys/epoll.h>
#elif defined(BMW_USE_KQUEUE)
#include <sys/event.h>
#endif

int bmw_loop_init(bmw_event_loop_t *loop) {
    memset(loop, 0, sizeof(*loop));
    loop->running = false;
    loop->fd_count = 0;

#ifdef BMW_USE_EPOLL
    loop->epoll_fd = epoll_create1(0);
    if (loop->epoll_fd < 0) return -1;
#elif defined(BMW_USE_KQUEUE)
    loop->kqueue_fd = kqueue();
    if (loop->kqueue_fd < 0) return -1;
#endif

    return 0;
}

int bmw_loop_add_fd(bmw_event_loop_t *loop, bmw_socket_t fd, int events,
                    bmw_fd_callback_t cb, void *userdata) {
    if (loop->fd_count >= BMW_MAX_FDS) return -1;

    int idx = loop->fd_count++;
    loop->fds[idx].fd = fd;
    loop->fds[idx].events = events;
    loop->fds[idx].callback = cb;
    loop->fds[idx].userdata = userdata;
    loop->fds[idx].active = true;

#ifdef BMW_USE_EPOLL
    struct epoll_event ev = {0};
    ev.data.fd = fd;
    if (events & BMW_EVENT_READ) ev.events |= EPOLLIN;
    if (events & BMW_EVENT_WRITE) ev.events |= EPOLLOUT;
    epoll_ctl(loop->epoll_fd, EPOLL_CTL_ADD, fd, &ev);
#elif defined(BMW_USE_KQUEUE)
    struct kevent kev[2];
    int n = 0;
    if (events & BMW_EVENT_READ)
        EV_SET(&kev[n++], fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
    if (events & BMW_EVENT_WRITE)
        EV_SET(&kev[n++], fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, NULL);
    kevent(loop->kqueue_fd, kev, n, NULL, 0, NULL);
#endif

    return 0;
}

int bmw_loop_mod_fd(bmw_event_loop_t *loop, bmw_socket_t fd, int events) {
    for (int i = 0; i < loop->fd_count; i++) {
        if (loop->fds[i].fd == fd && loop->fds[i].active) {
            loop->fds[i].events = events;
#ifdef BMW_USE_EPOLL
            struct epoll_event ev = {0};
            ev.data.fd = fd;
            if (events & BMW_EVENT_READ) ev.events |= EPOLLIN;
            if (events & BMW_EVENT_WRITE) ev.events |= EPOLLOUT;
            epoll_ctl(loop->epoll_fd, EPOLL_CTL_MOD, fd, &ev);
#endif
            return 0;
        }
    }
    return -1;
}

void bmw_loop_remove_fd(bmw_event_loop_t *loop, bmw_socket_t fd) {
    for (int i = 0; i < loop->fd_count; i++) {
        if (loop->fds[i].fd == fd) {
            loop->fds[i].active = false;
#ifdef BMW_USE_EPOLL
            epoll_ctl(loop->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
#endif
            /* Compact the array */
            loop->fds[i] = loop->fds[--loop->fd_count];
            return;
        }
    }
}

int bmw_loop_run(bmw_event_loop_t *loop) {
    loop->running = true;

    while (loop->running) {
        /* Periodic tick: dispatch ~once per second so modules can run
         * timeouts (slowloris/idle-conn eviction). Without this the
         * http_on_tick / wal_tcp_tick handlers were dead code. */
        if (loop->tick_cb) {
            uint32_t now_s = (uint32_t)time(NULL);
            if (now_s - loop->last_tick_ms >= 1) {
                loop->tick_cb(loop->tick_userdata);
                loop->last_tick_ms = now_s;
            }
        }

#ifdef BMW_USE_EPOLL
        struct epoll_event events[64];
        int n = epoll_wait(loop->epoll_fd, events, 64, 50);
        for (int i = 0; i < n; i++) {
            bmw_socket_t fd = events[i].data.fd;
            int ev = 0;
            if (events[i].events & EPOLLIN) ev |= BMW_EVENT_READ;
            if (events[i].events & EPOLLOUT) ev |= BMW_EVENT_WRITE;
            for (int j = 0; j < loop->fd_count; j++) {
                if (loop->fds[j].fd == fd && loop->fds[j].active) {
                    loop->fds[j].callback(fd, ev, loop->fds[j].userdata);
                    break;
                }
            }
        }
#elif defined(BMW_USE_KQUEUE)
        struct kevent events[64];
        struct timespec ts = {0, 50000000}; /* 50ms */
        int n = kevent(loop->kqueue_fd, NULL, 0, events, 64, &ts);
        for (int i = 0; i < n; i++) {
            bmw_socket_t fd = (bmw_socket_t)events[i].ident;
            int ev = 0;
            if (events[i].filter == EVFILT_READ) ev |= BMW_EVENT_READ;
            if (events[i].filter == EVFILT_WRITE) ev |= BMW_EVENT_WRITE;
            for (int j = 0; j < loop->fd_count; j++) {
                if (loop->fds[j].fd == fd && loop->fds[j].active) {
                    loop->fds[j].callback(fd, ev, loop->fds[j].userdata);
                    break;
                }
            }
        }
#else
        /* WSAPoll / select fallback */
#ifdef _WIN32
        WSAPOLLFD pfds[BMW_MAX_FDS];
#else
        struct pollfd pfds[BMW_MAX_FDS];
#endif
        int nfds = 0;
        for (int i = 0; i < loop->fd_count; i++) {
            if (!loop->fds[i].active) continue;
            pfds[nfds].fd = loop->fds[i].fd;
            pfds[nfds].events = 0;
            if (loop->fds[i].events & BMW_EVENT_READ) pfds[nfds].events |= POLLIN;
            if (loop->fds[i].events & BMW_EVENT_WRITE) pfds[nfds].events |= POLLOUT;
            pfds[nfds].revents = 0;
            nfds++;
        }

#ifdef _WIN32
        int ret = WSAPoll(pfds, nfds, 50);
#else
        int ret = poll(pfds, nfds, 50);
#endif
        if (ret > 0) {
            int pfd_idx = 0;
            for (int i = 0; i < loop->fd_count && pfd_idx < nfds; i++) {
                if (!loop->fds[i].active) continue;
                if (pfds[pfd_idx].revents) {
                    int ev = 0;
                    if (pfds[pfd_idx].revents & POLLIN) ev |= BMW_EVENT_READ;
                    if (pfds[pfd_idx].revents & POLLOUT) ev |= BMW_EVENT_WRITE;
                    loop->fds[i].callback(loop->fds[i].fd, ev, loop->fds[i].userdata);
                }
                pfd_idx++;
            }
        }
#endif
    }
    return 0;
}

void bmw_loop_stop(bmw_event_loop_t *loop) {
    loop->running = false;
}

void bmw_loop_set_tick(bmw_event_loop_t *loop, void (*cb)(void *), void *userdata) {
    loop->tick_cb = cb;
    loop->tick_userdata = userdata;
    loop->last_tick_ms = (uint32_t)time(NULL);
}

void bmw_loop_destroy(bmw_event_loop_t *loop) {
#ifdef BMW_USE_EPOLL
    if (loop->epoll_fd >= 0) close(loop->epoll_fd);
#elif defined(BMW_USE_KQUEUE)
    if (loop->kqueue_fd >= 0) close(loop->kqueue_fd);
#endif
    memset(loop, 0, sizeof(*loop));
}
