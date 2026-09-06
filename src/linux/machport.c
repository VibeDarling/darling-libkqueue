/*
 * Copyright (c) 2017 Lubos Dolezel
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <mach/message.h>
#include <darling/emulation/linux_premigration/ext/for-libkqueue.h>

/*
 * kqchan fds (kn_dupfd) are Darwin file descriptors managed by darwinkernel.
 * darwinkernel translates them to the real underlying Linux socket fd for us.
 * Therefore we MUST use the emulated recv()/send() (routed through
 * darwinkernel), NOT raw Linux syscalls (which would hit the wrong fd).
 */
#include <darlingserver/rpc-supplement.h>

#include "private.h"

#ifdef DARLING_DEBUG
extern void KQ_DLOG(const char* format, ...);
#define KQ_DLOG(...) KQ_DLOG(__VA_ARGS__)
#else
#define KQ_DLOG(...) ((void)0)
#endif
extern int __simple_sprintf(char *buffer, const char* format, ...);

/* True raw Linux socket syscalls via inline asm (bypass any darwinkernel
 * override of linux_syscall / emulated recv). aarch64 syscall numbers. */
/* True raw Linux socket syscalls via inline asm (bypass any darwinkernel
 * override of linux_syscall / emulated recv). aarch64 syscall numbers.
 * Args forced into ABI registers x0-x5, syscall number into x8. */
#if defined(__aarch64__) || defined(__arm64__)
#define RAW_NR_getsockname 204
#define RAW_NR_sendto      206
#define RAW_NR_recvfrom    207
static long raw_syscall6(long nr, long a1, long a2, long a3, long a4, long a5, long a6) {
    register long r0 __asm__("x0") = a1;
    register long r1 __asm__("x1") = a2;
    register long r2 __asm__("x2") = a3;
    register long r3 __asm__("x3") = a4;
    register long r4 __asm__("x4") = a5;
    register long r5 __asm__("x5") = a6;
    register long r8 __asm__("x8") = nr;
    __asm__ volatile("svc #0" : "+r"(r0)
        : "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5), "r"(r8)
        : "cc", "memory");
    return r0;
}
#elif defined(__x86_64__)
#define RAW_NR_getsockname 51
#define RAW_NR_sendto      44
#define RAW_NR_recvfrom    45
static long raw_syscall6(long nr, long a1, long a2, long a3, long a4, long a5, long a6) {
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8  __asm__("r8")  = a5;
    register long r9  __asm__("r9")  = a6;
    __asm__ volatile("syscall" : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
    return ret;
}
#elif defined(__i386__)
#define RAW_NR_getsockname 367
#define RAW_NR_sendto      369
#define RAW_NR_recvfrom    371
static long raw_syscall6(long nr, long a1, long a2, long a3, long a4, long a5, long a6) {
    long ret;
    __asm__ volatile(
        "pushl %%ebp\n\t"
        "movl %7, %%ebp\n\t"
        "int $0x80\n\t"
        "popl %%ebp\n\t"
        : "=a"(ret)
        : "0"(nr), "b"(a1), "c"(a2), "d"(a3), "S"(a4), "D"(a5), "m"(a6)
        : "memory"
    );
    return ret;
}
#endif

static long raw_recvfrom(int fd, void* buf, unsigned long len) {
    return raw_syscall6(RAW_NR_recvfrom, fd, (long)buf, len, 0, 0, 0);
}
static long raw_sendto(int fd, const void* buf, unsigned long len) {
    return raw_syscall6(RAW_NR_sendto, fd, (long)buf, len, 0, 0, 0);
}
static long raw_getsockname(int fd, void* addr, void* addrlen) {
    return raw_syscall6(RAW_NR_getsockname, fd, (long)addr, (long)addrlen, 0, 0, 0);
}

int
evfilt_machport_copyout(struct kevent64_s *dst, struct knote *src, void *ptr)
{
    struct epoll_event * const ev = (struct epoll_event *) ptr;
	dserver_kqchan_call_notification_t notification;
	dserver_kqchan_call_mach_port_read_t call;
	dserver_kqchan_reply_mach_port_read_t reply = {0};
	int rv;

	KQ_DLOG("machport_copyout: ENTER src=%p dst=%p dupfd=%d ev=%p\n", (void*)src, (void*)dst, src->kdata.kn_dupfd, (void*)ev);
    kevent_int_to_64(&src->kev, dst);

	// Validate that kn_dupfd is actually a socket before reading it. The
	// kqueue/epoll machinery can occasionally hand us a knote whose kn_dupfd is
	// stale or points at a non-socket (e.g. an eventfd). Reading from such an
	// fd would fail and (previously) abort the process. Instead, drop the event
	// so the (valid) kqchan socket's own events can still be delivered.
	{
		char ksock[64];
		unsigned int ksocklen = sizeof(ksock);
		long ksockrv = raw_getsockname(src->kdata.kn_dupfd, ksock, &ksocklen);
		if (ksockrv < 0) {
			KQ_DLOG("machport_copyout: dupfd=%d is not a socket (rv=%ld), dropping event\n", src->kdata.kn_dupfd, ksockrv);
			return -1;
		}
	}

	// first, read the notification (RAW recvfrom, since kn_dupfd is a raw Linux socket)
	rv = (int)raw_recvfrom(src->kdata.kn_dupfd, &notification, sizeof(notification));
	KQ_DLOG("machport_copyout: RAW recvfrom rv=%d errno=%d\n", rv, errno);
	if (rv < 0) {
		dbg_printf("evfilt_machport_copyout() reading notification failed: %d (%s)", errno, strerror(errno));
		return -1;
	}

	if (notification.header.number != dserver_kqchan_msgnum_notification) {
		dbg_puts("evfilt_machport_copyout() read invalid notification");
		return -1;
	}

	// next, request the data
	call.header.number = dserver_kqchan_msgnum_mach_port_read;
	call.header.pid = getpid();
	call.header.tid = THREAD_ID;
	call.default_buffer = (uint64_t)&src->kn_extra_buffer[0];
	call.default_buffer_size = sizeof(src->kn_extra_buffer);
	rv = (int)raw_sendto(src->kdata.kn_dupfd, &call, sizeof(call));
	if (rv < 0) {
		dbg_printf("evfilt_machport_copyout() sending request failed: %d (%s)", errno, strerror(errno));
		return -1;
	}

	// now, read the reply
	rv = (int)raw_recvfrom(src->kdata.kn_dupfd, &reply, sizeof(reply));
	if (rv < 0) {
		dbg_printf("evfilt_machport_copyout() reading reply failed: %d (%s)", errno, strerror(errno));
		return -1;
	}

	if (reply.header.number != dserver_kqchan_msgnum_mach_port_read) {
		dbg_puts("evfilt_machport_copyout() read invalid reply");
		return -1;
	}

	if (reply.header.code == 0xdead) {
		// server indicated there was actually no event available to read right now;
		// drop the event
		dst->filter = EVFILT_DROP;
		return 0;
	}

	if (reply.header.code != 0) {
		// FIXME: the returned code is actually a Linux code (but strerror is provided by Darwin libc here)
		dbg_printf("evfilt_machport_copyout() server indicated failure: %d (%s)", -reply.header.code, strerror(-reply.header.code));
		return -1;
	}

	if (reply.kev.flags != 0)
		dst->flags = reply.kev.flags;
	dst->data = reply.kev.data;
	dst->ext[0] = reply.kev.ext[0];
	dst->ext[1] = reply.kev.ext[1];
	dst->fflags = reply.kev.fflags;

	// TODO: we need to properly support kevent_qos with regards to the data_out argument;
	//       this is what's supposed to be passed in as the default buffer, not a buffer of our own.

    return (0);
}

int
evfilt_machport_knote_create(struct filter *filt, struct knote *kn)
{
    struct epoll_event ev;
    int port = kn->kev.ident;

    /* Convert the kevent into an epoll_event */
    kn->data.events = EPOLLIN;
    kn->kn_epollfd = filter_epfd(filt);

    memset(&ev, 0, sizeof(ev));
    ev.events = kn->data.events;
    ev.data.ptr = kn;

	int status = _dserver_rpc_kqchan_mach_port_open_4libkqueue(port, (void*)kn->kev.ext[0], kn->kev.ext[1], kn->kev.fflags, &kn->kdata.kn_dupfd);
	if (status < 0) {
		dbg_printf("evfilt_machport_open: %s", strerror(-status));
		return (-1);
	}

	dbg_printf("evfilt_machport_open: listening to FD %d for events %d", kn->kdata.kn_dupfd, ev.events);
	{
		char ksabuf[64]; unsigned int ksl = sizeof(ksabuf);
		long kgs = raw_getsockname(kn->kdata.kn_dupfd, ksabuf, &ksl);
		KQ_DLOG("machport_knote_create: kn=%p kn_dupfd=%d raw getsockname rv=%ld\n", (void*)kn, kn->kdata.kn_dupfd, kgs);
	}

    fcntl(kn->kdata.kn_dupfd, F_SETFD, FD_CLOEXEC);

    if (epoll_ctl(kn->kn_epollfd, EPOLL_CTL_ADD, kn->kdata.kn_dupfd, &ev) < 0) {
        dbg_printf("epoll_ctl(2): %s", strerror(errno));
        return (-1);
    }
    return 0;
}

int
evfilt_machport_knote_modify(struct filter *filt, struct knote *kn, 
        const struct kevent64_s *kev)
{
	dserver_kqchan_call_mach_port_modify_t call;
	dserver_kqchan_reply_mach_port_modify_t reply = {0};
	int rv;

	call.header.number = dserver_kqchan_msgnum_mach_port_modify;
	call.header.pid = getpid();
	call.header.tid = THREAD_ID;
	call.receive_buffer = kev->ext[0];
	call.receive_buffer_size = kev->ext[1];
	call.saved_filter_flags = kev->fflags;

	rv = (int)raw_sendto(kn->kdata.kn_dupfd, &call, sizeof(call));
	if (rv < 0) {
		dbg_printf("evfilt_machport_knote_modify send failed: %d (%s)", errno, strerror(errno));
		return -1;
	}

	rv = (int)raw_recvfrom(kn->kdata.kn_dupfd, &reply, sizeof(reply));
	if (rv < 0) {
		dbg_printf("evfilt_machport_knote_modify recv failed: %d (%s)", errno, strerror(errno));
		return -1;
	}

	if (reply.header.number != dserver_kqchan_msgnum_mach_port_modify) {
		dbg_puts("evfilt_machport_knote_modify invalid reply");
		return -1;
	}

	if (reply.header.code != 0) {
		// FIXME: same as in copyout: Linux code but Darwin strerror
		dbg_printf("evfilt_machport_knote_modify call failed: %d (%s)", -reply.header.code, strerror(-reply.header.code));
		return -1;
	}

    return 0;
}

int
evfilt_machport_knote_delete(struct filter *filt, struct knote *kn)
{
    if ((kn->kev.flags & EV_DISABLE) == 0) {
        if (epoll_ctl(kn->kn_epollfd, EPOLL_CTL_DEL, kn->kdata.kn_dupfd, NULL) < 0) {
            dbg_perror("epoll_ctl(2)");
            return (-1);
        }
    }

	(void) __close_for_kqueue(kn->kdata.kn_dupfd);
	kn->kdata.kn_dupfd = -1;
	return 0;
}

int
evfilt_machport_knote_enable(struct filter *filt, struct knote *kn)
{
    struct epoll_event ev;

    memset(&ev, 0, sizeof(ev));
    ev.events = kn->data.events;
    ev.data.ptr = kn;

	dbg_printf("enabling machport knote with ID=%llu for events %d", kn->kev.ident, ev.events);

	if (epoll_ctl(kn->kn_epollfd, EPOLL_CTL_ADD, kn->kdata.kn_dupfd, &ev) < 0) {
		dbg_perror("epoll_ctl(2)");
		return (-1);
	}
	return (0);
}

int
evfilt_machport_knote_disable(struct filter *filt, struct knote *kn)
{
	dbg_printf("disable machport knote with ID=%llu", kn->kev.ident);
	if (epoll_ctl(kn->kn_epollfd, EPOLL_CTL_DEL, kn->kdata.kn_dupfd, NULL) < 0) {
		dbg_perror("epoll_ctl(2)");
		return (-1);
	}
	return (0);
}

const struct filter evfilt_machport = {
    EVFILT_MACHPORT,
    NULL,
    NULL,
    evfilt_machport_copyout,
    evfilt_machport_knote_create,
    evfilt_machport_knote_modify,
    evfilt_machport_knote_delete,
    evfilt_machport_knote_enable,
    evfilt_machport_knote_disable,         
};
