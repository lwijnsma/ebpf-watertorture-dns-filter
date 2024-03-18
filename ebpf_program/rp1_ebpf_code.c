/*
eBPF code for RP1
Copyright (C) 2024 Ferran Tufan, Laurens Wijnsma

SPDX-License-Identifier: GPL-2.0-or-later

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

Based on https://ebpf-go.dev/guides/getting-started,
and code snippets sourced from NLnet Labs and PowerDNS
*/

#include <endian.h>
#include <stdint.h>
#include <linux/string.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
        __uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
        __type(value, uint8_t[254]);
        __uint(key_size, 0);
        __uint(max_entries, 8192);
        __uint(map_extra, 5);
} all_qnames SEC(".maps");

/*
 * Struct to store the DNS header.
 * Copyright 2020, NLnet Labs, All rights reserved.
 * Original Licence: BSD 3-Clause License
 */
struct dnshdr {
  uint16_t id;
  union {
  	struct {
#if BYTE_ORDER == LITTLE_ENDIAN
  		uint8_t  rd     : 1;
  		uint8_t  tc     : 1;
  		uint8_t  aa     : 1;
  		uint8_t  opcode : 4;
  		uint8_t  qr     : 1;

  		uint8_t  rcode  : 4;
  		uint8_t  cd     : 1;
  		uint8_t  ad     : 1;
  		uint8_t  z      : 1;
  		uint8_t  ra     : 1;
#elif BYTE_ORDER == BIG_ENDIAN || BYTE_ORDER == PDP_ENDIAN
  		uint8_t  qr     : 1;
  		uint8_t  opcode : 4;
  		uint8_t  aa     : 1;
  		uint8_t  tc     : 1;
  		uint8_t  rd     : 1;

  		uint8_t  ra     : 1;
  		uint8_t  z      : 1;
  		uint8_t  ad     : 1;
  		uint8_t  cd     : 1;
  		uint8_t  rcode  : 4;
#endif
  	}        as_bits_and_pieces;
  	uint16_t as_value;
  } flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
};

/*
 * Helper pointer to parse incoming dns packets.
 * Copyright 2020, NLnet Labs, All rights reserved.
 * Original Licence: BSD 3-Clause License
 */
struct cursor {
	void *pos;
	void *end;
};

 
/**
* Parse a domain name from a DNS packet.
* Copyright 2021, PowerDNS.
* source: https://github.com/PowerDNS/pdns/blob/c44a98688997aa28a383f07e9167374491258dc1/contrib/xdp-logging-middleware.ebpf.src#L9
* Original Licence: GPL v2, derivative work
*
* Transform '(3)www(3)os3(2)nl(0)' to '.www.os3.nl'
*/
static inline void parse_dname(struct cursor* c, uint8_t *dname) {
  uint8_t qname_byte;
  int length = 0;

  for (int i = 0; i < 254; i++) {
    bpf_probe_read_kernel(&qname_byte, sizeof(qname_byte), c->pos);

    c->pos += 1;
    if (length == 0) {
      if (qname_byte == 0 || qname_byte > 63) {
        break;
      }
      length += qname_byte;
      dname[i] = 46;
    } else {
      length--;
      if (qname_byte >= 'A' && qname_byte <= 'Z') {
        dname[i] = qname_byte + ('a' - 'A');
      } else {
        dname[i] = qname_byte;
        }
      }
  }

}


SEC("xdp") 
int ebpf_rp1_main(struct xdp_md *ctx) {
    // Used for cursor
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    if ((data + sizeof(struct ethhdr) + 1) > data_end) {
        return XDP_PASS;
    }
    struct ethhdr *eth = data;
    // Offset, will be incremented various times
    uint64_t nho = sizeof(*eth);

    uint8_t is_udp = 0;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        // Next header is IPv4
        if ((data + nho + sizeof(struct iphdr) + 1) > data_end) {
            return XDP_PASS;
        }
        struct iphdr *iph = data + nho;
        nho += sizeof(*iph);
        //bpf_printk("IPv4 packet found, source address is %pI4, dst address is %pI4", &iph->saddr, &iph->daddr);
        is_udp = iph->protocol == IPPROTO_UDP ? 1 : 0;
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        // Next header is IPv6
        if ((data + nho + sizeof(struct ipv6hdr) + 1) > data_end) {
            return XDP_PASS;
        }
        struct ipv6hdr *ip6h = data + nho;
        nho += sizeof(*ip6h);
        //bpf_printk("IPv6 packet found, source address is %pI6, dst address is %pI6", &ip6h->saddr, &ip6h->daddr);
        is_udp = ip6h->nexthdr == IPPROTO_UDP ? 1 : 0;
    }

    // If not UDP, pass
    if (is_udp != 1) {
        return XDP_PASS;
    }

    // Minimum size of DNS query is 5 bytes:
    // 3 bytes for qname, 2 bytes for class
    if ((data + nho + sizeof(struct udphdr) + sizeof(struct dnshdr) + 5 + 1) > data_end) {
        return XDP_PASS;
    }

    // Extract UDP and DNS headers
    struct udphdr *udph = data + nho;
    nho += sizeof(*udph);
    struct dnshdr *dnsh = data + nho;
    nho += sizeof(*dnsh);

    //bpf_printk("UDP packet found, source port is %d, dst port is %d", bpf_ntohs(udph->source), bpf_ntohs(udph->dest));

    if (bpf_ntohs(udph->dest) == 53  // udp/53 is desttination
       && dnsh->flags.as_bits_and_pieces.qr == 0 // QR bit is set to query
       && dnsh->qdcount >= 1 // query count is ge 1, should never be larger than 1 though
    ) {
        // parse_dname expects cursor of type struct cursor
        // create it, even if we don't use it in the rest of our code
        struct cursor dns_cursor;
        dns_cursor.pos = data + nho;
        dns_cursor.end = data_end;

        // Assign qname variable
        uint8_t qname[254];
        __builtin_memset(&qname, 0, sizeof(qname));

        // put value into qname
        parse_dname(&dns_cursor, &qname);

        //bpf_printk("Potential DNS query detected, qname %s", qname);
        uint8_t qname_peek = bpf_map_peek_elem(&all_qnames, &qname);
        if (qname_peek == 0) {
            //bpf_printk("'%s' may be part of bloom filter, query allowed", qname);
        } else {
            //bpf_printk("'%s' is definitely not in bloom filter, query will be dropped (XDP_DROP)", qname);
            return XDP_DROP;
        }
    }

    return XDP_PASS; 
}

char __license[] SEC("license") = "GPL v2";
