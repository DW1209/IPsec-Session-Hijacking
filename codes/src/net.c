#include <netdb.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "net.h"
#include "esp.h"
#include "transport.h"

uint16_t cal_ipv4_cksm(struct iphdr iphdr) {
    // [TODO]: Finish IP checksum calculation
}

uint8_t *dissect_ip(Net *self, uint8_t *pkt, size_t pkt_len) {
    // [TODO]: Collect information from pkt.
    // Return payload of network layer
}

Net *fmt_net_rep(Net *self) {
    // [TODO]: Fill up self->ip4hdr (prepare to send)

    return self;
}

void init_net(Net *self) {
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    self->src_ip   = (char*) malloc(INET_ADDRSTRLEN * sizeof(char));
    self->dst_ip   = (char*) malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_src_ip = (char*) malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_dst_ip = (char*) malloc(INET_ADDRSTRLEN * sizeof(char));
    self->hdrlen   = sizeof(struct iphdr);
    self->dissect  = dissect_ip;
    self->fmt_rep  = fmt_net_rep;
}
