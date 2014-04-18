#ifndef ZMAP_SEND_LINUX_H
#define ZMAP_SEND_LINUX_H

#include "../lib/includes.h"
#include <sys/ioctl.h>

#if defined(ZMAP_SEND_BSD_H) || defined(ZMAP_SEND_PFRING_H)
#error "Don't include send-bsd.h and send-pfring.h with send-linux.h"
#endif

// Dummy sockaddr for sendto
static struct sockaddr_ll sockaddr;


sock_t get_socket(void)
{
	sock_t sock;
        sock.sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock.sock <= 0) {
		log_fatal("send", "couldn't create socket. "
			  "Are you root? Error: %s\n", strerror(errno));
	}
	return sock;
}

int send_run_init(sock_t socket)
{
	// get source interface index
	struct ifreq if_idx;
	memset(&if_idx, 0, sizeof(struct ifreq));
	if (strlen(zconf.iface) >= IFNAMSIZ) {
		log_error("send", "device interface name (%s) too long\n",
				zconf.iface);
		return EXIT_FAILURE;
	}
	strncpy(if_idx.ifr_name, zconf.iface, IFNAMSIZ-1);
	if (ioctl(socket.sock, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		return EXIT_FAILURE;
	}
	int ifindex = if_idx.ifr_ifindex;

	// find source IP address associated with the dev from which we're sending.
	// while we won't use this address for sending packets, we need the address
	// to set certain socket options and it's easiest to just use the primary
	// address the OS believes is associated.
	struct ifreq if_ip;
	memset(&if_ip, 0, sizeof(struct ifreq));
	strncpy(if_ip.ifr_name, zconf.iface, IFNAMSIZ-1);
	if (ioctl(socket.sock, SIOCGIFADDR, &if_ip) < 0) {
		perror("SIOCGIFADDR");
		return EXIT_FAILURE;
	}
	// destination address for the socket
	memset((void*) &sockaddr, 0, sizeof(struct sockaddr_ll));
	sockaddr.sll_ifindex = ifindex;
	sockaddr.sll_halen = ETH_ALEN;
	memcpy(sockaddr.sll_addr, zconf.gw_mac, ETH_ALEN);
	return EXIT_SUCCESS;
}

int send_packet(sock_t sock, void *buf, int len)
{
	return sendto(sock.sock, buf, len, 0,
		      (struct sockaddr *) &sockaddr,
		      sizeof(struct sockaddr_ll));
}

#endif /* ZMAP_SEND_LINUX_H */
