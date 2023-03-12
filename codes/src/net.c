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
    
    uint32_t sum = 0;
    uint16_t *buffer = (uint16_t*) &iphdr;

    for (size_t i = 0; i < iphdr.ihl * 2; i++) {
        sum += htons(buffer[i]);
    }

    while (sum >> 16) {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    return ~sum;
}

uint8_t *dissect_ip(Net *self, uint8_t *pkt, size_t pkt_len) {
    // [TODO]: Collect information from pkt.
    // Return payload of network layer

    if (pkt_len < self->hdrlen) {
        fprintf(stderr, "%s error: the packet length is too short.\n", __func__);
        return NULL;
    }

    struct iphdr *ip4hdr = (struct iphdr*) pkt;

    self->ip4hdr = *ip4hdr;
    self->plen   = pkt_len - self->hdrlen;
    self->pro    = (Proto) ip4hdr->protocol;

    inet_ntop(AF_INET, &(ip4hdr->saddr), self->src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip4hdr->daddr), self->dst_ip, INET_ADDRSTRLEN);

    return pkt + self->hdrlen;
}

Net *fmt_net_rep(Net *self) {
    // [TODO]: Fill up self->ip4hdr (prepare to send)

    self->ip4hdr.version  = 4;
    self->ip4hdr.ihl      = 5;
    self->ip4hdr.tos      = 0;
    self->ip4hdr.tot_len  = htons(self->hdrlen + self->plen);
    self->ip4hdr.id       = htons(0x01);
    self->ip4hdr.frag_off = 0;
    self->ip4hdr.ttl      = 64;
    self->ip4hdr.protocol = self->pro;
    self->ip4hdr.saddr    = inet_addr(self->x_src_ip);
    self->ip4hdr.daddr    = inet_addr(self->x_dst_ip);
    self->ip4hdr.check    = 0;
    self->ip4hdr.check    = cal_ipv4_cksm(self->ip4hdr);

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
