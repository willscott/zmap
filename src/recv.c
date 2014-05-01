/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>

#include <pcap.h>
#include <pcap/pcap.h>

#include <pfring.h>

#include "recv.h"

#include "../lib/includes.h"
#include "../lib/logger.h"
#include "../lib/pbm.h"

#include "state.h"
#include "validate.h"
#include "fieldset.h"
#include "expression.h"
#include "probe_modules/probe_modules.h"
#include "output_modules/output_modules.h"

#define PCAP_PROMISC 1
#define PCAP_TIMEOUT 1000

static uint32_t num_src_ports;
static recv_sock_t sock;

// bitmap of observed IP addresses
static uint8_t **seen = NULL;

static u_char fake_eth_hdr[65535];

void handle_packet(uint32_t buflen, const u_char *bytes) {
	if ((sizeof(struct ip) + (zconf.send_ip_pkts ? 0 : sizeof(struct ether_header))) > buflen) {
		// buffer not large enough to contain ethernet
		// and ip headers. further action would overrun buf
		return;
	}

	struct ip *ip_hdr = (struct ip *) &bytes[(zconf.send_ip_pkts ? 0 :
						  sizeof(struct ether_header))];

	uint32_t src_ip = ip_hdr->ip_src.s_addr;

	uint32_t validation[VALIDATE_BYTES/sizeof(uint8_t)];
	// TODO: for TTL exceeded messages, ip_hdr->saddr is going to be different
	// and we must calculate off potential payload message instead
	validate_gen(ip_hdr->ip_dst.s_addr, ip_hdr->ip_src.s_addr, (uint8_t *) validation);

	if (!zconf.probe_module->validate_packet(ip_hdr, buflen - (zconf.send_ip_pkts ? 0 : sizeof(struct ether_header)),
				&src_ip, validation)) {
		return;
	}

	int is_repeat = pbm_check(seen, ntohl(src_ip));

	fieldset_t *fs = fs_new_fieldset();
	fs_add_ip_fields(fs, ip_hdr);
	// HACK:
	// probe modules (for whatever reason) expect the full ethernet frame
	// in process_packet. For VPN, we only get back an IP frame.
	// Here, we fake an ethernet frame (which is initialized to
	// have ETH_P_IP proto and 00s for dest/src).
	if (zconf.send_ip_pkts) {
		if (buflen > sizeof(fake_eth_hdr)) {
			buflen = sizeof(fake_eth_hdr);
		}
		memcpy(&fake_eth_hdr[sizeof(struct ether_header)], bytes, buflen);
		bytes = fake_eth_hdr;
	}
	zconf.probe_module->process_packet(bytes, buflen, fs);
	fs_add_system_fields(fs, is_repeat, zsend.complete);
	int success_index = zconf.fsconf.success_index;
	assert(success_index < fs->len);
	int is_success = fs_get_uint64_by_index(fs, success_index);

	if (is_success) {
		zrecv.success_total++;
		if (!is_repeat) {
			zrecv.success_unique++;
			pbm_set(seen, ntohl(src_ip));
		}
		if (zsend.complete) {
			zrecv.cooldown_total++;
			if (!is_repeat) {
				zrecv.cooldown_unique++;
			}
		}
	} else {
		zrecv.failure_total++;
	}
	fieldset_t *o = NULL;
	// we need to translate the data provided by the probe module
	// into a fieldset that can be used by the output module
	if (!is_success && zconf.filter_unsuccessful) {
		goto cleanup;
	}
	if (is_repeat && zconf.filter_duplicates) {
		goto cleanup;
	}
	if (!evaluate_expression(zconf.filter.expression, fs)) {
		goto cleanup;
	}
	o = translate_fieldset(fs, &zconf.fsconf.translation);
	if (zconf.output_module && zconf.output_module->process_ip) {
		zconf.output_module->process_ip(o);
	}
cleanup:
	fs_free(fs);
	free(o);
	if (zconf.output_module && zconf.output_module->update
			&& !(zrecv.success_unique % zconf.output_module->update_interval)) {
		zconf.output_module->update(&zconf, &zsend, &zrecv);
	}
}

void packet_cb(u_char __attribute__((__unused__)) *user,
		const struct pcap_pkthdr *p, const u_char *bytes)
{
	if (!p) {
		return;
	}
	if (zrecv.success_unique >= zconf.max_results) {
		// Libpcap can process multiple packets per pcap_dispatch;
		// we need to throw out results once we've
		// gotten our --max-results worth.
		return;
	}
	// length of entire packet captured by libpcap
	uint32_t buflen = (uint32_t) p->caplen;

	handle_packet(buflen, bytes);
}

static char hex[] = "0123456789ABCDEF";

char* etheraddr_string(const u_char *ep, char *buf) {
	u_int i, j;
	char *cp;

	cp = buf;
	if((j = *ep >> 4) != 0)
		*cp++ = hex[j];
	else
		*cp++ = '0';

	*cp++ = hex[*ep++ & 0xf];

	for(i = 5; (int)--i >= 0;) {
		*cp++ = ':';
		if((j = *ep >> 4) != 0)
			*cp++ = hex[j];
		else
			*cp++ = '0';

		*cp++ = hex[*ep++ & 0xf];
	}

	*cp = '\0';
	return (buf);
}

#ifdef PFRING
void recv_packet() {
	u_char *p = malloc(1024);
	struct pfring_pkthdr *h = malloc(sizeof(struct pfring_pkthdr));
        int ret = pfring_recv(sock.pfring_sock, &p, 1024, h, 0);
	if (ret < 0) {
		log_fatal("recv", "pfring_recv error");
	}
	if (ret != 0) {
		if(h->ts.tv_sec == 0) {
			memset((void*)&h->extended_hdr.parsed_pkt, 0, sizeof(struct pkt_parsing_info));
			pfring_parse_pkt((u_char*)p, (struct pfring_pkthdr*)h, 5, 1, 1);
		}

		handle_packet(h->caplen, p);

		char buf1[64];
		char buf2[64];
		printf("[%s -> %s]\n",
		       etheraddr_string(h->extended_hdr.parsed_pkt.smac, buf1),
		       etheraddr_string(h->extended_hdr.parsed_pkt.dmac, buf2));
	}
	free(p);
	free(h);
}

void recv_init() {
	sock.pfring_sock = pfring_open(zconf.iface, 128, 0);
	if (sock.pfring_sock == NULL) {
		perror("pfring_open");
		exit(1);
	}

	pfring_set_socket_mode(sock.pfring_sock, recv_only_mode);

	int err = pfring_enable_ring(sock.pfring_sock);
	if (err < 0) {
		perror("pfring_enable");
		exit(1);
	}
}

void recv_finish() {
	pfring_close(sock.pfring_sock);
	sock.pfring_sock = NULL;
}

int recv_update_stats(void)
{
	if (!sock.pfring_sock) {
		return EXIT_FAILURE;
	}
	pfring_stat pfst;
	if (pfring_stats(sock.pfring_sock, &pfst)) {
		log_error("recv", "unable to retrieve pfring statistics");
		return EXIT_FAILURE;
	} else {
		zrecv.pcap_recv = pfst.recv;
		zrecv.pcap_drop = pfst.drop;
	}
	return EXIT_SUCCESS;
}

#else
void recv_packet() {
	if (pcap_dispatch(sock.pc, -1, packet_cb, NULL) == -1) {
		log_fatal("recv", "pcap_dispatch error");
	}
}

void recv_init() {
	char errbuf[PCAP_ERRBUF_SIZE];
	sock.pc = pcap_open_live(zconf.iface, zconf.probe_module->pcap_snaplen,
			    PCAP_PROMISC, PCAP_TIMEOUT, errbuf);

	if (sock.pc == NULL) {
		log_fatal("recv", "could not open device %s: %s",
			  zconf.iface, errbuf);
	}
	struct bpf_program bpf;
	if (pcap_compile(sock.pc, &bpf, zconf.probe_module->pcap_filter, 1, 0) < 0) {
		log_fatal("recv", "couldn't compile filter");
	}
	if (pcap_setfilter(sock.pc, &bpf) < 0) {
		log_fatal("recv", "couldn't install filter");
	}
	// set pcap_dispatch to not hang if it never receives any packets
	// this could occur if you ever scan a small number of hosts as
	// documented in issue #74.
	if (pcap_setnonblock (sock.pc, 1, errbuf) == -1) {
		log_fatal("recv", "pcap_setnonblock error:%s", errbuf);
	}
}

void recv_finish() {
	pthread_mutex_lock(recv_ready_mutex);
	pcap_close(sock.pc);
	sock.pc = NULL;
	pthread_mutex_unlock(recv_ready_mutex);
}
int recv_update_stats(void)
{
	if (!sock.pc) {
		return EXIT_FAILURE;
	}
	struct pcap_stat pcst;
	if (pcap_stats(sock.pc, &pcst)) {
		log_error("recv", "unable to retrieve pcap statistics: %s",
			  pcap_geterr(sock.pc));
		return EXIT_FAILURE;
	} else {
		zrecv.pcap_recv = pcst.ps_recv;
		zrecv.pcap_drop = pcst.ps_drop;
		zrecv.pcap_ifdrop = pcst.ps_ifdrop;
	}
	return EXIT_SUCCESS;
}

#endif

int recv_run(pthread_mutex_t *recv_ready_mutex)
{
	log_trace("recv", "recv thread started");
	num_src_ports = zconf.source_port_last - zconf.source_port_first + 1;
	log_debug("recv", "capturing responses on %s", zconf.iface);
	if (!zconf.dryrun) {
		recv_init();
	}
	if (zconf.send_ip_pkts) {
		struct ether_header *eth = (struct ether_header *) fake_eth_hdr;
		memset(fake_eth_hdr, 0, sizeof(fake_eth_hdr));
		eth->ether_type = htons(ETHERTYPE_IP);
	}
	// initialize paged bitmap
	seen = pbm_init();
	if (zconf.filter_duplicates) {
		log_debug("recv", "duplicate responses will be excluded from output");
	} else {
		log_debug("recv", "duplicate responses will be included in output");
	}
	if (zconf.filter_unsuccessful) {
		log_debug("recv", "unsuccessful responses will be excluded from output");
	} else {
		log_debug("recv", "unsuccessful responses will be included in output");
	}

	pthread_mutex_lock(recv_ready_mutex);
	zconf.recv_ready = 1;
	pthread_mutex_unlock(recv_ready_mutex);
	zrecv.start = now();
	if (zconf.max_results == 0) {
		zconf.max_results = -1;
	}

	do {
		if (zconf.dryrun) {
			sleep(1);
		} else {
			recv_packet();
			if (zconf.max_results &&
			    zrecv.success_unique >= zconf.max_results) {
				break;
			}
		}
	} while (!(zsend.complete && (now()-zsend.finish > zconf.cooldown_secs)));
	zrecv.finish = now();
	// get final statistics before closing
	recv_update_stats();
	if (!zconf.dryrun) {
		recv_finish();
	}
	zrecv.complete = 1;
	log_debug("recv", "thread finished");
	return 0;
}
