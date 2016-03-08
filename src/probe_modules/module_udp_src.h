/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <unistd.h>

#include "aesrand.h"
#include "types.h"

#include "state.h"

typedef enum udp_src_payload_field_type
{
	UDP_DATA,
	UDP_SADDR_N, UDP_SADDR_A, UDP_DADDR_N, UDP_DADDR_A,
	UDP_SPORT_N, UDP_SPORT_A, UDP_DPORT_N, UDP_DPORT_A,
	UDP_RAND_BYTE,
	UDP_RAND_DIGIT,
	UDP_RAND_ALPHA,
	UDP_RAND_ALPHANUM
} udp_src_payload_field_type_t;

typedef struct udp_src_payload_field_type_def {
	const char *name;
	const char *desc;
	udp_src_payload_field_type_t ftype;
} udp_src_payload_field_type_def_t;

typedef struct udp_src_payload_field
{
	enum udp_src_payload_field_type ftype;
	unsigned int length;
	char *data;
} udp_src_payload_field_t;

typedef struct udp_src_payload_template
{
	unsigned int fcount;
	struct udp_src_payload_field **fields;
} udp_src_payload_template_t;

typedef struct udp_src_payload_output
{
	int length;
	char *data;
} udp_src_payload_output_t;

void udp_src_print_packet(FILE *fp, void* packet);

int udp_src_make_packet(void *buf, ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
		uint32_t *validation, int probe_num, void *arg);

int udp_src_validate_packet(const struct ip *ip_hdr, uint32_t len,
		__attribute__((unused))uint32_t *src_ip, uint32_t *validation);

int udp_src_do_validate_packet(const struct ip *ip_hdr, uint32_t len,
		__attribute__((unused))uint32_t *src_ip, uint32_t *validation,
		int num_ports);

extern const char *udp_src_unreach_strings[];
int udp_src_global_initialize(struct state_conf *conf);
int udp_src_global_cleanup(__attribute__((unused)) struct state_conf *zconf,
		__attribute__((unused)) struct state_send *zsend,
		__attribute__((unused)) struct state_recv *zrecv);

void udp_src_set_num_ports(int x);

void udp_src_template_add_field(udp_src_payload_template_t *t,
	udp_src_payload_field_type_t ftype, unsigned int length, char *data);

void udp_src_template_free(udp_src_payload_template_t *t);

int udp_src_template_build(udp_src_payload_template_t *t, char *out, unsigned int len, struct ip *ip_hdr, struct udphdr *udp_hdr, aesrand_t *aes);

int udp_src_template_field_lookup(char *vname, udp_src_payload_field_t *c);

udp_src_payload_template_t * udp_src_template_load(char *buf, unsigned int len);
