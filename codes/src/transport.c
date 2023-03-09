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
    uint16_t tcplen = htons(sizeof(struct tcphdr) + plen);

    sum += ((iphdr.saddr >> 16) & 0xFFFF) + (iphdr.saddr & 0xFFFF);
    sum += ((iphdr.daddr >> 16) & 0xFFFF) + (iphdr.daddr & 0xFFFF);
    sum += htons(iphdr.protocol);
    sum += tcplen;

    ptr = (uint16_t*) &tcphdr;
    for (int i = 0; i < sizeof(struct tcphdr) / 2; i++) {
        sum += *ptr++;
    }
    
    ptr = (uint16_t*) &pl;
    for (int i = 0; i < plen / 2; i++) {
        sum += *ptr++;
    }

    if (plen & 1) {
        sum += (pl[plen - 1] << 8);
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

    struct tcphdr *tcphdr = &self->thdr;

    if (strcmp(net->src_ip, net->x_src_ip) == 0 && strcmp(net->dst_ip, net->x_dst_ip) == 0 &&
        tcphdr->th_sport == htons(self->x_src_port) && tcphdr->th_dport == htons(self->x_dst_port)) {
        self->x_tx_seq = ntohl(tcphdr->th_ack);
        self->x_tx_ack = ntohl(tcphdr->th_seq + segm_len - (self->hdrlen + net->hdrlen + 14));
    }

    self->plen = segm_len - self->hdrlen;
    memcpy(self->pl, segm + self->hdrlen, self->plen);

    return self->pl;
}

Txp* fmt_tcp_rep(Txp *self, struct iphdr iphdr, uint8_t *data, size_t dlen) {
    // [TODO]: Fill up self->tcphdr (prepare to send)

    self->thdr.th_sport = self->x_src_port;
    self->thdr.th_dport = self->x_dst_port;
    self->thdr.th_seq   = htonl(self->x_tx_seq);
    self->thdr.th_ack   = htonl(self->x_tx_ack);
    self->thdr.th_off   = self->hdrlen / 4;
    self->thdr.th_flags = TH_ACK | TH_PUSH;
    self->thdr.th_win   = htons(BUFSIZE);
    self->thdr.th_sum   = 0;
    self->thdr.th_sum   = cal_tcp_cksm(iphdr, self->thdr, data, dlen);

    return self;
}

inline void init_txp(Txp *self) {
    self->pl = (uint8_t*) malloc(IP_MAXPACKET * sizeof(uint8_t));
    self->hdrlen = sizeof(struct tcphdr);
    self->dissect = dissect_tcp;
    self->fmt_rep = fmt_tcp_rep;
}

