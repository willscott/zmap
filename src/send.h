/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef SEND_H
#define SEND_H

#include "iterator.h"
#include <pfring.h>

typedef union {
    int sock;
    pfring *pfring_sock;
} sock_t;

sock_t get_socket(void);
sock_t get_dryrun_socket(void);
iterator_t* send_init(void);
int send_run(sock_t, shard_t*);

#endif //SEND_H
