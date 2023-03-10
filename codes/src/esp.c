#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <linux/pfkeyv2.h>

#include "esp.h"
#include "hmac.h"
#include "transport.h"

#define PFKEY_ALIGN8(len) (((len) + 0x07) & ~0x07)

EspHeader esp_hdr_rec;

void get_ik(int type, uint8_t *key) {
    // [TODO]: Dump authentication key from security association database (SADB)
    // (Ref. RFC2367 Section 2.3.4 & 2.4 & 3.1.10)

    int s = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);

    struct sadb_msg msg;

    bzero(&msg, sizeof(msg));
    msg.sadb_msg_version = PF_KEY_V2;
    msg.sadb_msg_type    = SADB_DUMP;
    msg.sadb_msg_satype  = type;
    msg.sadb_msg_len     = sizeof(msg) / 8;
    msg.sadb_msg_pid     = getpid();
    write(s, &msg, sizeof(msg));

    bool gotEOF = false;

    while (!gotEOF) {
        char buffer[BUFSIZE];
        read(s, &buffer, sizeof(buffer));
        struct sadb_msg *msgp = (struct sadb_msg*) &buffer;

        uint8_t  sadb_msg_type   = msgp->sadb_msg_type;
        uint8_t  sadb_msg_satype = msgp->sadb_msg_satype;
        uint16_t sadb_msg_len    = msgp->sadb_msg_len;

        if (sadb_msg_type == SADB_GET && sadb_msg_satype == type && sadb_msg_len >= sizeof(struct sadb_msg) / 8) {
            struct sadb_sa *sap = (struct sadb_sa*) msgp;
            if (sap->sadb_sa_auth == SADB_AALG_SHA1HMAC) {
                struct sadb_key *keyp = (struct sadb_key*) (((char *) sap) + PFKEY_ALIGN8(sap->sadb_sa_len));
                for (int i = 0; i < (keyp->sadb_key_bits + 7) / 8; i++) {
                    key[i] = (uint8_t)(keyp->sadb_key_bits >> (8 * i));
                }
            }
        }

        if (msgp->sadb_msg_seq == 0) {
            gotEOF = true;
        }
    }

    close(s);
}

void get_esp_key(Esp *self) {
    get_ik(SADB_SATYPE_ESP, self->esp_key);
}

uint8_t *set_esp_pad(Esp *self) {
    // [TODO]: Fill up self->pad and self->pad_len (Ref. RFC4303 Section 2.4)

    size_t padlen = 4 - ((self->plen + sizeof(self->tlr)) % 4);
    self->tlr.pad_len = padlen;
    
    self->pad = (uint8_t*) malloc(padlen * sizeof(uint8_t));
    for (size_t i = 0; i < padlen; i++) {
        self->pad[i] = (uint8_t)(rand() & 0xFF);
    }

    return self->pad;
}

uint8_t *set_esp_auth(
    Esp *self,
    ssize_t (*hmac)(
        uint8_t const*, size_t, uint8_t const*, size_t, uint8_t*
    )
) {
    if (!self || !hmac) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return NULL;
    }

    uint8_t buff[BUFSIZE];
    size_t esp_keylen = 16;
    size_t nb = 0;  // Number of bytes to be hashed
    ssize_t ret;

    // [TODO]: Put everything needed to be authenticated into buff and add up nb

    memcpy(buff, self->pl, self->plen);
    memcpy(buff + self->plen, self->pad, self->tlr.pad_len);
    nb += (self->plen + self->tlr.pad_len);

    ret = hmac(self->esp_key, esp_keylen, buff, nb, self->auth);

    if (ret == -1) {
        fprintf(stderr, "Error occurs when try to compute authentication data");
        return NULL;
    }

    self->authlen = ret;
    return self->auth;
}

uint8_t *dissect_esp(Esp *self, uint8_t *esp_pkt, size_t esp_len) {
    // [TODO]: Collect information from esp_pkt.
    // Return payload of ESP

    if (esp_len < sizeof(struct esp)) {
        fprintf(stderr, "%s error: the packet length is too short\n", __func__);
        return NULL;
    }

    size_t hdrlen = sizeof(EspHeader);
    size_t tlrlen = sizeof(EspTrailer);

    memcpy(&self->hdr, esp_pkt, hdrlen);
    memcpy(&self->tlr, esp_pkt + esp_len - tlrlen, tlrlen);

    self->pl   = esp_pkt + hdrlen;
    self->plen = esp_len - hdrlen - self->tlr.pad_len - tlrlen;
    self->pad  = esp_pkt + hdrlen + self->plen;

    return self->pl;
}

Esp *fmt_esp_rep(Esp *self, Proto p) {
    // [TODO]: Fill up ESP header and trailer (prepare to send)

    self->hdr.spi     = htonl(self->hdr.spi);
    self->hdr.seq     = htonl(self->hdr.seq);
    self->tlr.pad_len = (uint8_t)(self->set_padpl(self) - self->pad);
    self->tlr.nxt     = (uint8_t) p;

    return self;
}

void init_esp(Esp *self) {
    self->pl        = (uint8_t*) malloc(MAXESPPLEN * sizeof(uint8_t));
    self->pad       = (uint8_t*) malloc(MAXESPPADLEN * sizeof(uint8_t));
    self->auth      = (uint8_t*) malloc(HMAC96AUTHLEN * sizeof(uint8_t));
    self->authlen   = HMAC96AUTHLEN;
    self->esp_key   = (uint8_t*) malloc(BUFSIZE * sizeof(uint8_t));
    self->set_padpl = set_esp_pad;
    self->set_auth  = set_esp_auth;
    self->get_key   = get_esp_key;
    self->dissect   = dissect_esp;
    self->fmt_rep   = fmt_esp_rep;
}
