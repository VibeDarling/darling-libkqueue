/*
 * Copyright (c) 2017 Lubos Dolezel
 *
 * Permission to use this software for any purpose with or without a fee is
 * granted in case you meet license terms.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY CLAIMS ARISING IN A RELATION TO THE SOFTWARE OR THE USE
 * OR OTHER DEALINGS IN THE SOFTWARE.
 */

/*
 * EVFILT_FS on Linux.
 *
 * The original implementation watched a read fd on /proc/mounts for
 * EPOLLERR, which the kernel never raises for procfs files, so the filter
 * produced no events at all. launchd relies on the VQ_MOUNT event that this
 * filter is supposed to deliver (it dispatches all jobs when /var is
 * mounted by launchctl); without it, no job is ever started.
 *
 * This implementation polls /proc/mounts on a shared per-kqueue watcher
 * thread and raises an eventfd whenever the mount table changes.
 */

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <string.h>
#include <unistd.h>

#include "private.h"

#define FS_WATCH_MOUNTS "/proc/mounts"
#define FS_WATCH_BUF_SZ 16384
#define FS_WATCH_INTERVAL_US (500 * 1000)
/* Up to 8 concurrent kqueues monitoring filesystem mounts across the process.
 * In a typical container launchd and diskarbitrationd each create 1 kqueue with
 * EVFILT_FS; 8 provides generous headroom while keeping static allocation tiny. */
#define FS_WATCH_MAX 8

struct fs_watch {
    int in_use;
    int epfd;
    int efd;
    int count;
    int stop;
    pthread_t tid;
    char prev[FS_WATCH_BUF_SZ];
    size_t prev_len;
};

static struct fs_watch fs_watches[FS_WATCH_MAX];
static pthread_mutex_t fs_watches_lock = PTHREAD_MUTEX_INITIALIZER;

static void
fs_watch_read_mounts(char* buf, size_t buf_sz, size_t* len_out)
{
    int fd = open(FS_WATCH_MOUNTS, O_RDONLY);
    size_t total = 0;

    if (fd == -1) {
        *len_out = 0;
        return;
    }

    while (total < buf_sz - 1) {
        ssize_t n = read(fd, buf + total, buf_sz - 1 - total);
        if (n <= 0)
            break;
        total += (size_t)n;
    }
    close(fd);
    buf[total] = '\0';
    *len_out = total;
}

static void*
fs_watch_thread(void* arg)
{
    struct fs_watch* w = (struct fs_watch*)arg;
    char cur[FS_WATCH_BUF_SZ];
    size_t cur_len = 0;

    fs_watch_read_mounts(cur, sizeof(cur), &cur_len);
    /* seed prev with the current table so the first event only fires
     * on a real change after the knote was added */
    if (w->prev_len == 0) {
        memcpy(w->prev, cur, cur_len < FS_WATCH_BUF_SZ - 1 ? cur_len : FS_WATCH_BUF_SZ - 1);
        w->prev_len = cur_len < FS_WATCH_BUF_SZ - 1 ? cur_len : FS_WATCH_BUF_SZ - 1;
    }

    while (!w->stop) {
        struct timespec ts = { 0, FS_WATCH_INTERVAL_US * 1000 };
        nanosleep(&ts, NULL);

        if (w->stop)
            break;

        fs_watch_read_mounts(cur, sizeof(cur), &cur_len);
        if (cur_len != w->prev_len || memcmp(cur, w->prev, cur_len < w->prev_len ? cur_len : w->prev_len) != 0) {
            size_t copy_len = cur_len < FS_WATCH_BUF_SZ - 1 ? cur_len : FS_WATCH_BUF_SZ - 1;
            memcpy(w->prev, cur, copy_len);
            w->prev_len = copy_len;

            uint64_t one = 1;
            (void)write(w->efd, &one, sizeof(one));
        }
    }
    return NULL;
}

static struct fs_watch*
fs_watch_get(int epfd)
{
    struct fs_watch* found = NULL;

    pthread_mutex_lock(&fs_watches_lock);
    for (int i = 0; i < FS_WATCH_MAX; i++) {
        if (fs_watches[i].in_use && fs_watches[i].epfd == epfd) {
            found = &fs_watches[i];
            break;
        }
    }
    if (!found) {
        for (int i = 0; i < FS_WATCH_MAX; i++) {
            if (!fs_watches[i].in_use) {
                found = &fs_watches[i];
                break;
            }
        }
    }
    if (found && !found->in_use) {
        found->in_use = 1;
        found->epfd = epfd;
        found->count = 0;
        found->stop = 0;
        found->prev[0] = '\0';
        found->prev_len = 0;
        found->efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (found->efd == -1) {
            found->in_use = 0;
            found = NULL;
        } else if (pthread_create(&found->tid, NULL, fs_watch_thread, found) != 0) {
            close(found->efd);
            found->in_use = 0;
            found = NULL;
        }
    }
    pthread_mutex_unlock(&fs_watches_lock);
    return found;
}

static void
fs_watch_put(struct fs_watch* w)
{
    pthread_mutex_lock(&fs_watches_lock);
    w->count--;
    if (w->count <= 0) {
        w->stop = 1;
        pthread_mutex_unlock(&fs_watches_lock);
        pthread_join(w->tid, NULL);
        close(w->efd);
        pthread_mutex_lock(&fs_watches_lock);
        w->in_use = 0;
    }
    pthread_mutex_unlock(&fs_watches_lock);
}

int
evfilt_fs_copyout(struct kevent64_s* dst, struct knote* src, void* ptr)
{
    struct epoll_event* const ev = (struct epoll_event*)ptr;

    epoll_event_dump(ev);
    kevent_int_to_64(&src->kev, dst);

    // TODO: filter out events
    // TODO: provide real event fflags
    dst->fflags = VQ_MOUNT;

    /* Drain the eventfd so this event is reported only once per mount
     * change. The watcher thread raises the eventfd (write) on a mount
     * table change or on the one-time seed; because the eventfd is
     * EFD_NONBLOCK and nothing else reads it, leaving it unread would
     * keep it readable forever and re-fire EVFILT_FS on every kevent()
     * call. That floods launchd's kqueue demand loop with repeated
     * VQ_MOUNT events (a mach_msg_overwrite storm) and prevents it from
     * doing real work. Reading here resets the counter to zero.
     * src->kdata.kn_dupfd is the eventfd (set in knote_create). */
    {
        uint64_t val;
        (void)read(src->kdata.kn_dupfd, &val, sizeof(val));
    }

    return (0);
}

int
evfilt_fs_knote_create(struct filter* filt, struct knote* kn)
{
    struct epoll_event ev;
    struct fs_watch* w;

    w = fs_watch_get(filter_epfd(filt));
    if (w == NULL) {
        dbg_printf("fs_watch_get: %s", strerror(errno));
        return (-1);
    }

    kn->data.events = EPOLLIN;
    kn->kn_epollfd = filter_epfd(filt);
    kn->kdata.kn_dupfd = w->efd;
    w->count++;
    int is_first = (w->count == 1);

    memset(&ev, 0, sizeof(ev));
    ev.events = kn->data.events;
    ev.data.ptr = kn;

    if (epoll_ctl(kn->kn_epollfd, EPOLL_CTL_ADD, kn->kdata.kn_dupfd, &ev) < 0) {
        dbg_printf("epoll_ctl(2): %s", strerror(errno));
        w->count--;
        return (-1);
    }

    /* Seed event: report the current mount table state immediately.
     * launchd starts RunAtLoad jobs when it receives the first VQ_MOUNT
     * event; on systems where the mount table does not change after
     * launchd starts (e.g. darling containers), no further VQ_MOUNT
     * event would ever arrive and no job would ever be dispatched. */
    if (is_first) {
        uint64_t one = 1;
        (void)write(w->efd, &one, sizeof(one));
    }
    return 0;
}

int
evfilt_fs_knote_modify(struct filter* filt, struct knote* kn,
    const struct kevent64_s* kev)
{
    return 0;
}

int
evfilt_fs_knote_delete(struct filter* filt, struct knote* kn)
{
    struct fs_watch* w;

    if ((kn->kev.flags & EV_DISABLE) == 0) {
        if (epoll_ctl(kn->kn_epollfd, EPOLL_CTL_DEL, kn->kdata.kn_dupfd, NULL) < 0) {
            dbg_perror("epoll_ctl(2)");
            return (-1);
        }
    }

    pthread_mutex_lock(&fs_watches_lock);
    for (int i = 0; i < FS_WATCH_MAX; i++) {
        if (fs_watches[i].in_use && fs_watches[i].efd == kn->kdata.kn_dupfd) {
            w = &fs_watches[i];
            break;
        }
    }
    pthread_mutex_unlock(&fs_watches_lock);

    if (w)
        fs_watch_put(w);

    kn->kdata.kn_dupfd = -1;
    return 0;
}

int
evfilt_fs_knote_enable(struct filter* filt, struct knote* kn)
{
    struct epoll_event ev;

    memset(&ev, 0, sizeof(ev));
    ev.events = kn->data.events;
    ev.data.ptr = kn;

    if (epoll_ctl(kn->kn_epollfd, EPOLL_CTL_ADD, kn->kdata.kn_dupfd, &ev) < 0) {
        dbg_perror("epoll_ctl(2)");
        return (-1);
    }
    return (0);
}

int
evfilt_fs_knote_disable(struct filter* filt, struct knote* kn)
{
    if (epoll_ctl(kn->kn_epollfd, EPOLL_CTL_DEL, kn->kdata.kn_dupfd, NULL) < 0) {
        dbg_perror("epoll_ctl(2)");
        return (-1);
    }
    return (0);
}

const struct filter evfilt_fs = {
    EVFILT_FS,
    NULL,
    NULL,
    evfilt_fs_copyout,
    evfilt_fs_knote_create,
    evfilt_fs_knote_modify,
    evfilt_fs_knote_delete,
    evfilt_fs_knote_enable,
    evfilt_fs_knote_disable,
};
