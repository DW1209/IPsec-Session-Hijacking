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

void key_print(struct sadb_ext *ext, uint8_t *input_key) {
    unsigned char *p;
	int bits, tmp = 0;
    struct sadb_key *key = (struct sadb_key*) ext;

	for (p = (unsigned char*)(key + 1), bits = key->sadb_key_bits; bits > 0; p++, bits -= 8, tmp++) {
		memcpy(input_key + tmp * key->sadb_key_bits / 8, p, key->sadb_key_bits / 8);
	}		
}


void print_sadb_msg(struct sadb_msg *msg, int msglen, uint8_t *key) {
	if (msglen != msg->sadb_msg_len * 8) {
		return;
	}

	if (msg->sadb_msg_version != PF_KEY_V2) {
		return;
	}
	
	if (msglen == sizeof(struct sadb_msg)){
		return;
	}
		
	msglen -= sizeof(struct sadb_msg);
	struct sadb_ext *ext = (struct sadb_ext*)(msg + 1);

	while (msglen > 0) {
        if (ext->sadb_ext_type == SADB_EXT_KEY_AUTH || 
            ext->sadb_ext_type == SADB_EXT_KEY_ENCRYPT) {
            key_print(ext, key);
        }

		msglen -= ext->sadb_ext_len << 3;
		ext = (struct sadb_ext*)((char*)ext + (ext->sadb_ext_len << 3));
	}
}

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

    int  msglen = 0;
    bool gotEOF = false;
    char buffer[BUFSIZE];

    while (!gotEOF) {
        msglen = read(s, &buffer, sizeof(buffer));
        struct sadb_msg *msgp = (struct sadb_msg*) &buffer;
        print_sadb_msg(msgp, msglen, key);
        if (msgp->sadb_msg_seq == 0) {
            gotEOF = true;
        }
    }

    struct sadb_ext *ext = (struct sadb_ext*) buffer;
    while ((char*) ext < buffer + msglen) {
        if (ext->sadb_ext_type == SADB_EXT_KEY_AUTH || 
            ext->sadb_ext_type == SADB_EXT_KEY_ENCRYPT) {
            struct sadb_key *key_ext = (struct sadb_key*) ext;
            if (key_ext->sadb_key_bits > 0) {
                memcpy(key, (unsigned char*)(key_ext + 1), key_ext->sadb_key_bits / 8);
                break;
            }
        }

        ext = (struct sadb_ext*)((char*) ext + PFKEY_ALIGN8(ext->sadb_ext_len));
    }

    close(s);
}

void get_esp_key(Esp *self) {
    get_ik(SADB_SATYPE_ESP, self->esp_key);
}

uint8_t *set_esp_pad(Esp *self) {
    // [TODO]: Fill up self->pad and self->pad_len (Ref. RFC4303 Section 2.4)

    size_t esplen = sizeof(EspHeader) + self->plen + sizeof(EspTrailer);
    self->tlr.pad_len = 4 - (esplen % 4);
    
    for (size_t i = 0; i < self->tlr.pad_len; i++) {
        self->pad[i] = (uint8_t)(i + 1);
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

    memcpy(buff, &self->hdr, sizeof(EspHeader));
    nb += sizeof(EspHeader);

    memcpy(buff + nb, self->pl, self->plen);
    nb += self->plen;

    memcpy(buff + nb, self->pad, self->tlr.pad_len);
    nb += self->tlr.pad_len;

    memcpy(buff + nb, &self->tlr, sizeof(EspTrailer));
    nb += sizeof(EspTrailer);

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

    size_t hdrlen = sizeof(EspHeader);
    size_t tlrlen = sizeof(EspTrailer);

    if (esp_len < hdrlen + tlrlen) {
        fprintf(stderr, "%s error: the packet length is too short\n", __func__);
        return NULL;
    }

    EspHeader  *hdr = (EspHeader*)  esp_pkt;
    EspTrailer *tlr = (EspTrailer*)(esp_pkt + esp_len - self->authlen - tlrlen);

    self->hdr.spi     = ntohl(hdr->spi);
    self->hdr.seq     = ntohl(hdr->seq);
    self->pl          = esp_pkt + hdrlen;
    self->plen        = esp_len - (hdrlen + tlrlen + tlr->pad_len + self->authlen);
    self->pad         = esp_pkt + hdrlen + self->plen;
    self->tlr.pad_len = tlr->pad_len;
    self->tlr.nxt     = tlr->nxt;

    return self->pl;
}

Esp *fmt_esp_rep(Esp *self, Proto p) {
    // [TODO]: Fill up ESP header and trailer (prepare to send)

    self->hdr.spi = htonl(esp_hdr_rec.spi);
    self->hdr.seq = htonl(esp_hdr_rec.seq + 0x01);
    self->tlr.nxt = (uint8_t) p;

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
