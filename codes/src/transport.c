#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>

#include "net.h"
#include "transport.h"

uint16_t cal_tcp_cksm(struct iphdr iphdr, struct tcphdr tcphdr, uint8_t *pl, int plen) {
    // [TODO]: Finish TCP checksum calculation

    uint16_t *ptr;
    uint32_t sum = 0;

    sum += (htons(iphdr.saddr) & 0xFFFF) + (htons(iphdr.saddr >> 16) & 0xFFFF);
    sum += (htons(iphdr.daddr) & 0xFFFF) + (htons(iphdr.daddr >> 16) & 0xFFFF);
    sum += (uint16_t)(IPPROTO_TCP);
    sum += (uint16_t)(sizeof(tcphdr) + plen);

    ptr = (uint16_t*) &tcphdr;
    for (int i = 0; i < sizeof(struct tcphdr) / 2; i++) {
        sum += htons(ptr[i]);
    }
    
    ptr = (uint16_t*) pl;
    for (int i = 0; i < plen / 2; i++) {
        sum += htons(ptr[i]);
    }

    if (plen & 1) {
        sum += (uint16_t)(pl[plen - 1] << 8);
    }

    while (sum >> 16) {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    return ~sum;
}

uint8_t* dissect_tcp(Net *net, Txp *self, uint8_t *segm, size_t segm_len) {
    // [TODO]: Collect information from segm
    // (Check IP addr & port to determine the next seq and ack value)
    // Return payload of TCP

    if (segm_len < self->hdrlen) {
        fprintf(stderr, "%s error: the packet length is too short\n", __func__);
        return NULL;
    }

    struct tcphdr *tcphdr = (struct tcphdr*) segm;
    
    self->thdr     = *tcphdr;
    self->plen     = segm_len - self->hdrlen;
    self->pl       = segm + self->hdrlen;

    return self->pl;
}

Txp* fmt_tcp_rep(Txp *self, struct iphdr iphdr, uint8_t *data, size_t dlen) {
    // [TODO]: Fill up self->tcphdr (prepare to send)

    self->pl = data;

    self->thdr.th_sport = htons(self->x_src_port);
    self->thdr.th_dport = htons(self->x_dst_port);
    self->thdr.th_seq   = htonl(self->x_tx_seq);
    self->thdr.th_ack   = htonl(self->x_tx_ack);
    self->thdr.th_flags = TH_ACK | TH_PUSH;
    self->thdr.th_sum   = 0;
    self->thdr.th_sum   = htons(cal_tcp_cksm(iphdr, self->thdr, data, dlen));

    return self;
}

inline void init_txp(Txp *self) {
    self->pl = (uint8_t*) malloc(IP_MAXPACKET * sizeof(uint8_t));
    self->hdrlen = sizeof(struct tcphdr);
    self->dissect = dissect_tcp;
    self->fmt_rep = fmt_tcp_rep;
}

