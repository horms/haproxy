/*
 * File descriptors management functions.
 *
 * Copyright 2000-2008 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include <common/compat.h>
#include <common/config.h>

#include <types/protocols.h>

#include <proto/fd.h>
#include <proto/port_range.h>

struct fdtab *fdtab = NULL;     /* array of all the file descriptors */
struct fdinfo *fdinfo = NULL;   /* less-often used infos for file descriptors */
int maxfd;                      /* # of the highest fd + 1 */
int totalconn;                  /* total # of terminated sessions */
int actconn;                    /* # of active sessions */

struct poller pollers[MAX_POLLERS];
struct poller cur_poller;
int nbpollers = 0;

static struct socket_cache *socket_cache = NULL;

/* Deletes an FD from the fdsets, and recomputes the maxfd limit.
 * The file descriptor is also closed.
 */
void fd_delete(int fd)
{
	EV_FD_CLO(fd);
	port_range_release_port(fdinfo[fd].port_range, fdinfo[fd].local_port);
	fdinfo[fd].port_range = NULL;
	close(fd);
	fdtab[fd].state = FD_STCLOSE;

	while ((maxfd-1 >= 0) && (fdtab[maxfd-1].state == FD_STCLOSE))
		maxfd--;
}


/* disable the specified poller */
void disable_poller(const char *poller_name)
{
	int p;

	for (p = 0; p < nbpollers; p++)
		if (strcmp(pollers[p].name, poller_name) == 0)
			pollers[p].pref = 0;
}

/*
 * Initialize the pollers till the best one is found.
 * If none works, returns 0, otherwise 1.
 */
int init_pollers()
{
	int p;
	struct poller *bp;


	do {
		bp = NULL;
		for (p = 0; p < nbpollers; p++)
			if (!bp || (pollers[p].pref > bp->pref))
				bp = &pollers[p];

		if (!bp || bp->pref == 0)
			break;

		if (bp->init(bp)) {
			memcpy(&cur_poller, bp, sizeof(*bp));
			return 1;
		}
	} while (!bp || bp->pref == 0);
	return 0;
}

/*
 * Deinitialize the pollers.
 */
void deinit_pollers() {

	struct poller *bp;
	int p;

	for (p = 0; p < nbpollers; p++) {
		bp = &pollers[p];

		if (bp && bp->pref)
			bp->term(bp);
	}
}

/*
 * Lists the known pollers on <out>.
 * Should be performed only before initialization.
 */
int list_pollers(FILE *out)
{
	int p;
	int last, next;
	int usable;
	struct poller *bp;

	fprintf(out, "Available polling systems :\n");

	usable = 0;
	bp = NULL;
	last = next = -1;
	while (1) {
		for (p = 0; p < nbpollers; p++) {
			if ((next < 0 || pollers[p].pref > next)
			    && (last < 0 || pollers[p].pref < last)) {
				next = pollers[p].pref;
				if (!bp || (pollers[p].pref > bp->pref))
					bp = &pollers[p];
			}
		}

		if (next == -1)
			break;

		for (p = 0; p < nbpollers; p++) {
			if (pollers[p].pref == next) {
				fprintf(out, " %10s : ", pollers[p].name);
				if (pollers[p].pref == 0)
					fprintf(out, "disabled, ");
				else
					fprintf(out, "pref=%3d, ", pollers[p].pref);
				if (pollers[p].test(&pollers[p])) {
					fprintf(out, " test result OK");
					if (next > 0)
						usable++;
				} else {
					fprintf(out, " test result FAILED");
					if (bp == &pollers[p])
						bp = NULL;
				}
				fprintf(out, "\n");
			}
		}
		last = next;
		next = -1;
	};
	fprintf(out, "Total: %d (%d usable), will use %s.\n", nbpollers, usable, bp ? bp->name : "none");
	return 0;
}

/*
 * Some pollers may lose their connection after a fork(). It may be necessary
 * to create initialize part of them again. Returns 0 in case of failure,
 * otherwise 1. The fork() function may be NULL if unused. In case of error,
 * the the current poller is destroyed and the caller is responsible for trying
 * another one by calling init_pollers() again.
 */
int fork_poller()
{
	if (cur_poller.fork) {
		if (cur_poller.fork(&cur_poller))
			return 1;
		cur_poller.term(&cur_poller);
		return 0;
	}
	return 1;
}

enum {
	SC_AVAILABLE,
	SC_INVALID,
	SC_INUSE
};

void socket_cache_make_all_available(void)
{
	struct socket_cache *e;

	for (e = socket_cache; e; e = e->next)
		e->state = SC_AVAILABLE;
}

void socket_cache_gc(void)
{
	struct socket_cache *e, *next, *prev = NULL;

	for (e = socket_cache; e; e = next) {
		next = e->next;
		if (e->state == SC_INUSE) {
			prev = e;
			continue;
		}
		if (prev)
			prev->next = e->next;
		else
			socket_cache = e->next;
		if (e->state != SC_INVALID)
			fd_delete(e->fd);
		free(e);
	}
}

static void socket_cache_body_assign(struct socket_cache *e,
				     const struct listener *listener)
{
	e->sock_type = listener->proto->sock_type;
	e->sock_prot = listener->proto->sock_prot;
	e->sock_addrlen = listener->proto->sock_addrlen;
	e->options = listener->options &
		(LI_O_NOLINGER|LI_O_FOREIGN|LI_O_NOQUICKACK|LI_O_DEF_ACCEPT);
	e->addr = listener->addr;
	e->maxconn = listener->maxconn;
	e->backlog = listener->backlog;
	memcpy(&e->perm, &listener->perm, sizeof(e->perm));
	e->maxseg = listener->maxseg;
}

#ifndef offsetof
#define offsetof(type, member) ((size_t)&((type *)NULL)->member)
#endif

static int socket_cache_cmp(const struct socket_cache *a,
			    const struct socket_cache *b)
{
	size_t start = offsetof(typeof(*a), sock_type);
	size_t end = offsetof(typeof(*a), addr) +
			offsetof(typeof(a->addr), ss_family) +
			sizeof(a->addr.ss_family);

	if (memcmp((const char *)a + start, (const char *)b + start,
		   end - start))
		return 1; /* Mismatch */

	/* For AF_INET and AF_INET6 either address may be
	 * the wildcard address
	 */
	switch (a->addr.ss_family) {
	case AF_INET:
		{
		struct sockaddr_in *addr_a = (struct sockaddr_in *)&(a->addr);
		struct sockaddr_in *addr_b = (struct sockaddr_in *)&(b->addr);
		if (addr_a->sin_port != addr_b->sin_port)
			return 1; /* Mismatch */
		if (addr_a->sin_addr.s_addr != INADDR_ANY &&
		    addr_b->sin_addr.s_addr != INADDR_ANY &&
		    addr_a->sin_addr.s_addr != addr_b->sin_addr.s_addr)
			return 1; /* Mismatch */
		}
		break;
	case AF_INET6:
		{
		struct sockaddr_in6 *addr_a = (struct sockaddr_in6 *)&(a->addr);
		struct sockaddr_in6 *addr_b = (struct sockaddr_in6 *)&(b->addr);
		if (addr_a->sin6_port != addr_b->sin6_port)
			return 1; /* Mismatch */
		if (memcmp(&(addr_a->sin6_addr), &in6addr_any,
			   sizeof(addr_a->sin6_addr)) &&
		    memcmp(&(addr_b->sin6_addr), &in6addr_any,
			   sizeof(in6addr_any)) &&
		    memcmp(&(addr_b->sin6_addr), &in6addr_any,
			   sizeof(in6addr_any)))
			return 1; /* Mismatch */
		}
		break;
	}

	return 0; /* Match */
}

static int socket_cache_cmp_detail(const struct socket_cache *a,
				const struct socket_cache *b)
{
	size_t start = offsetof(typeof(*a), addr);
	size_t end = offsetof(typeof(*a), maxseg) + sizeof(a->maxseg);

	if ((a->interface || b->interface) &&
	    (!a->interface || !b->interface ||
	      strcmp(a->interface, b->interface)))
 	     return -1;

	return memcmp((const char *)a + start, (const char *)b + start,
		      end - start);
}

int socket_cache_get(const struct listener *listener)
{
	struct socket_cache a = {}, *b;

	socket_cache_body_assign(&a, listener);
	a.interface = listener->interface;

	/* First find a cache entry which is available and whose type,
	 * protocol and address match. Wildcard matches are allowed for
	 " the address. For a valid configuration there should only ever
	 * be at most one match.
	 *
	 * If a match is found verify the listener's details incuding
	 * an exact match on the address. If this is successful then
	 " use the fd associated with the socket_cache entry. Else close
	 * its file descriptor and invalidate it as it is of no use and
	 * and will prevent binding of a fresh socket.
	 *
	 * By performing a wildcard match on the address any sockets that
	 " would prevent the binding of a new socket to a requsted address,
	 " wildcard or otherwise, are found. By then closing the file
	 * descriptor of non-exact matches bind can subsequently be called
	 * for the requested address.
	 */
	for (b = socket_cache; b; b = b->next) {
		if (b->state == SC_AVAILABLE && !socket_cache_cmp(&a, b)) {
			if (!socket_cache_cmp_detail(&a, b)) {
				b->state = SC_INUSE;
				return b->fd;
			}
			fd_delete(b->fd);
			b->state = SC_INVALID;
			break;
		}
	}

	return -1;
}

int socket_cache_add(int fd, struct listener *listener)
{
	struct socket_cache *e;

	e = calloc(1, sizeof(struct socket_cache));
	if (!e)
		return -1;

	e->fd = fd;
	e->state = SC_INUSE;
	if (listener->interface) {
		e->interface = strdup(listener->interface);
		if (!e->interface) {
			free(e);
			return -1;
		}
	}
	socket_cache_body_assign(e, listener);

	if (socket_cache)
		e->next = socket_cache;
	socket_cache = e;

	return 0;
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
