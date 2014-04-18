#ifndef ZMAP_SEND_PFRING_H
#define ZMAP_SEND_PFRING_H

#include "../lib/includes.h"
#include <sys/ioctl.h>

#if defined(ZMAP_SEND_BSD_H) || defined(ZMAP_SEND_LINUX_H)
#error "Don't include send-bsd.h and send-linux.h with send-pfring.h"
#endif

static pfring *ring;

sock_t get_socket(void)
{
	if (ring == NULL) {
		ring = pfring_open(zconf.iface, 128, 0);
		if (ring == NULL) {
			goto fail;
		}

		pfring_set_socket_mode(ring, send_only_mode);

		int err = pfring_enable_ring(ring);
		if (err < 0) {
			goto fail;
		}
	}
	sock_t sock;
	sock.pfring_sock = ring;
	return sock;

 fail:
	log_fatal("send", "couldn't create pfring socket. "
		  "Are you root? Error: %s\n", strerror(errno));
}

int send_run_init(sock_t socket)
{
	(void) socket;

	// All init for pfring happens in get_socket
	return 0;
}

int send_packet(sock_t sock, void *buf, int len)
{
	return pfring_send(sock.pfring_sock, buf, len, 1);
}

#endif /* ZMAP_SEND_PFRING_H */
