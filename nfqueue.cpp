/**
 * Shamelessly adapted from
 * https://www.andersoncalixto.com.br/2015/11/using-nfqueue-and-libnetfilter_queue/
 */

#include <stdint.h>
#include <netinet/in.h>
#include <linux/in6.h>
#include <linux/netfilter.h>
#include <linux/types.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <map>
#include "packet_structs.h"
#include <string.h>
#include <vector>

struct packet_verdict_t {
  unsigned char *new_data;
  uint32_t new_data_length;
  u_int32_t verdict;
  int packet_id;
};

namespace IPDefragmenter {

/**
 * Stores a packet starting from the transport header.
 * The client of this struct is responsible for freeing the buffer
 */
struct Packet {
  u_char *data;
  int length;
};

/**
 * Stores a packet being reconstructed. These parts contain data from the
 * transport header onwards (i.e. transport header + payload).
 *
 * The client of this struct is responsible for freeing the buffer
 */
struct PartialPacket {
  u_char *data;
  int length;
};

/**
 * Taken from
 * https://networkengineering.stackexchange.com/questions/46514/identification-field-in-ipv4-header:
 * "In IPv4, the Identification (ID) field is a 16-bit value that is
 * unique for every datagram for a given source address, destination
 * address, and protocol, such that it does not repeat within the
 * maximum datagram lifetime (MDL) [RFC791] [RFC1122]. As currently
 * specified, all datagrams between a source and destination of a given
 * protocol must have unique IPv4 ID values over a period of this MDL,
 * which is typically interpreted as two minutes and is related to the
 * recommended reassembly timeout [RFC1122]. This uniqueness is
 * currently specified as for all datagrams, regardless of fragmentation
 * settings."
 *
 * Our convention: 128-bit key in this order: <source IP, dest IP, protocol,
 * identification number>
 *
 */
std::map<__uint128_t, std::vector<PartialPacket>> packet_fragments;

__uint128_t build_map_key(sniff_ip *ip) {
  __uint128_t key = 0;
  key = ip->ip_src.s_addr;                // 32-bit number
  key = (key << 32) | ip->ip_dst.s_addr;  // 32-bit number
  key = (key << 32) | ip->ip_p;           // 8-bit number
  key = (key << 8) | ip->ip_id;           // 16-bit number
  return key;
}

/**
 * Returns nullptr if the current `data` could not complete a packet (i.e. more
 * fragments are expected).
 *
 * Expects `data` to contain packet data starting from IP header (including it
 * as well).
 *
 * Otherwise (i.e. we have just reassembled the whole packet) returns the
 * reassembled payload, starting from the transport header. The returned pointer
 * should be freed by the caller.
 */
Packet *defrag(u_char *data, int total_length) {
  struct sniff_ip *ip = (struct sniff_ip *)data;
  int ip_header_length = IP_HL(ip) * 4;

  // is this not-fragmented ? (easy case)
  if (packet_fragments.count(build_map_key(ip)) == 0 &&
      ((ip->ip_off & IP_MF) == 0)) {
    printf("IP reassembly case 0 ¬¬'\n");
    u_char *buffer = new u_char[total_length - ip_header_length];
    memcpy(buffer, data + ip_header_length, total_length - ip_header_length);
    return new Packet{data : buffer, length : total_length - ip_header_length};
  }

  // it is fragmented =( life gets harder

  // case 1: we already received a fragment and are now receiving a middle
  // fragment
  if (packet_fragments.count(build_map_key(ip)) != 0 &&
      ((ip->ip_off & IP_MF) != 0)) {
    printf("IP reassembly case 1\n");
    auto &&packet_parts = packet_fragments[build_map_key(ip)];
    packet_parts.push_back(PartialPacket{data : data, length : total_length});
    return nullptr;
  }
  // case 2: we already received a fragment and are now receiving the LAST
  // fragment
  else if (packet_fragments.count(build_map_key(ip)) != 0 &&
           ((ip->ip_off & IP_MF) == 0)) {
    printf("IP reassembly case 2\n");
    auto &&packet_parts = packet_fragments[build_map_key(ip)];
    packet_parts.push_back(PartialPacket{data : data, length : total_length});

    int total_part_length = 0;
    for (auto &&packet_part : packet_parts) {
      total_part_length += packet_part.length;
    }

    Packet *packet = new Packet;
    packet->length = total_part_length;
    packet->data = new u_char[total_part_length];

    int incremental_part_length = 0;
    for (auto &&packet_part : packet_parts) {
      memcpy(packet->data + incremental_part_length, packet_part.data,
             packet_part.length);
      delete[] packet_part.data;
      incremental_part_length += packet_part.length;
    }

    packet_fragments.erase(build_map_key(ip));

    return packet;

  }
  // case 3: we had not received a fragment before. this if the first fragment
  else {
    printf("IP reassembly case 3\n");
    packet_fragments[build_map_key(ip)] = std::vector<PartialPacket>();
    auto &&packet_parts = packet_fragments[build_map_key(ip)];
    packet_parts.push_back(PartialPacket{data : data, length : total_length});
    return nullptr;
  }

  printf("Reached an impossible-to-reach code\n");
  exit(1);
}

}  // namespace IPDefragmenter

namespace HTTPDefragmenter {
void a() {}
}  // namespace HTTPDefragmenter

/**
 * `verdict` should be manipulated by the function to signal packet
 * modifications.
 */
static void print_pkt(struct nfq_data *tb, packet_verdict_t *verdict) {
  int id = 0;
  struct nfqnl_msg_packet_hdr *ph;
  struct nfqnl_msg_packet_hw *hwph;
  u_int32_t mark, ifi;
  int ret;
  unsigned char *data;
  struct iphdr *ip_info;

  ph = nfq_get_msg_packet_hdr(tb);
  if (ph) {
    id = ntohl(ph->packet_id);
    printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol),
           ph->hook, id);
  }

  hwph = nfq_get_packet_hw(tb);
  if (hwph) {
    int i, hlen = ntohs(hwph->hw_addrlen);

    printf("hw_src_addr=");
    for (i = 0; i < hlen - 1; i++) printf("%02x:", hwph->hw_addr[i]);
    printf("%02x ", hwph->hw_addr[hlen - 1]);
  }

  mark = nfq_get_nfmark(tb);
  if (mark) printf("mark=%u ", mark);

  ifi = nfq_get_indev(tb);
  if (ifi) printf("indev=%u ", ifi);

  ifi = nfq_get_outdev(tb);
  if (ifi) printf("outdev=%u ", ifi);
  ifi = nfq_get_physindev(tb);
  if (ifi) printf("physindev=%u ", ifi);

  ifi = nfq_get_physoutdev(tb);
  if (ifi) printf("physoutdev=%u ", ifi);

  ret = nfq_get_payload(tb, &data);
  if (ret >= 0) {
    printf("payload_len(ip+tcp+payload)=%d ", ret);
    // processPacketData (data, ret);
    struct sniff_ip *ip = (struct sniff_ip *)data;
    int ip_header_length = IP_HL(ip) * 4;
    printf("ip_header_length=%d ", ip_header_length);
    // if (ip->ip_p == IPPROTO_UDP) {
    //   struct sniff_udp *udp = (sniff_udp *)(data + ip_header_length);
    //   u_char *payload = data + ip_header_length + sizeof(sniff_udp);
    //   printf("Payload data:\n(%.*s)\n\n", udp->len - sizeof(sniff_udp),
    //          payload);
    //   payload[0] = 'A';
    //   udp->check = 0;
    //   verdict->new_data = data;
    //   verdict->new_data_length = ret;
    // }
    if (ip->ip_p != IPPROTO_TCP) {
      printf("Not a TCP packet. Skipping...\n\n");
      return;
    }

    struct sniff_tcp *tcp = (sniff_tcp *)(data + ip_header_length);
    int tcp_header_length = TH_OFF(tcp) * 4;
    int payload_length = ret - ip_header_length - tcp_header_length;
    printf("tcp_header_length=%d ", tcp_header_length);
    u_char *payload = data + ip_header_length + tcp_header_length;
    printf("Payload data:\n(%.*s)\n\n", payload_length, payload);

    IPDefragmenter::Packet *reassemble =
        IPDefragmenter::defrag((u_char *)ip, ret - ip_header_length);

    if (reassemble != nullptr) {
      tcp = (sniff_tcp *)reassemble->data;
      tcp_header_length = TH_OFF(tcp) * 4;
      payload_length = reassemble->length - tcp_header_length;
      payload = reassemble->data + tcp_header_length;
      printf("Just Reassembled packet:\n(%.*s)\n\n", payload_length, payload);
      delete[] reassemble->data;
      delete reassemble;
    }
  }
  fputc('\n', stdout);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
  packet_verdict_t verdict;
  verdict.new_data = NULL;
  verdict.new_data_length = 0;
  verdict.verdict = NF_ACCEPT;
  verdict.packet_id = ntohl(nfq_get_msg_packet_hdr(nfa)->packet_id);
  print_pkt(nfa, &verdict);

  printf("entering callback\n");
  return nfq_set_verdict(qh, verdict.packet_id, verdict.verdict,
                         verdict.new_data_length, verdict.new_data);
}

int main(int argc, char **argv) {
  struct nfq_handle *h;
  struct nfq_q_handle *qh;
  int fd;
  int rv;
  char buf[4096] __attribute__((aligned));

  printf("opening library handle\n");
  h = nfq_open();
  if (!h) {
    fprintf(stderr, "error during nfq_open()\n");
    exit(1);
  }

  printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
  if (nfq_unbind_pf(h, AF_INET) < 0) {
    fprintf(stderr, "error during nfq_unbind_pf()\n");
    perror("");
    exit(1);
  }

  printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
  if (nfq_bind_pf(h, AF_INET) < 0) {
    fprintf(stderr, "error during nfq_bind_pf()\n");
    exit(1);
  }

  printf("binding this socket to queue '0'\n");
  qh = nfq_create_queue(h, 0, &cb, NULL);
  if (!qh) {
    fprintf(stderr, "error during nfq_create_queue()\n");
    exit(1);
  }

  printf("setting copy_packet mode\n");
  if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
    fprintf(stderr, "can't set packet_copy mode\n");
    exit(1);
  }

  fd = nfq_fd(h);

  // para el tema del loss:   while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv
  // >= 0)

  while ((rv = recv(fd, buf, sizeof(buf), 0))) {
    printf("pkt received\n");
    nfq_handle_packet(h, buf, rv);
  }

  printf("unbinding from queue 0\n");
  nfq_destroy_queue(qh);

#ifdef INSANE
  /* normally, applications SHOULD NOT issue this command, since
   * it detaches other programs/sockets from AF_INET, too ! */
  printf("unbinding from AF_INET\n");
  nfq_unbind_pf(h, AF_INET);
#endif

  printf("closing library handle\n");
  nfq_close(h);

  exit(0);
}