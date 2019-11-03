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

/**
 * Returns the header length in units of byte
 */
int get_tcp_header_length(sniff_tcp *tcp) { return TH_OFF(tcp) * 4; }

// TODO: This does not work if fragments come out-of-order
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
  key = (key << 8) | ip->ip_p;            // 8-bit number
  key = (key << 16) | ip->ip_id;          // 16-bit number
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

/**
 * Provides TCP content deduplication (by ignoring retransmissions, for example)
 */
namespace TCPStreamer {

/**
 * Stores out-of-order bytes received through TCP but not immediately
 * consummable (because previous bytes still have not arrived).
 *
 * Clients of this struct are responsible for freeing `data`
 */
struct OOOBytes {
  u_int begin_seq_num;
  u_int next_seq_num;
  u_int length;
  u_char *data;
};

/**
 * Stores information for a single source_ip:source_port:dest_ip:dest_port
 * quartet
 */
struct TCPFlowStatus {
  /**
   * initial sequence number used
   */
  u_int initial_seqnum;
  /**
   * Quantity of bytes received until the moment. The next expected sequence
   * number is, therefore, `initial_seqnum` + `received_bytes_count`
   */
  u_int received_bytes_count = 0;
  /**
   * True iff we receive a FIN packet.
   */
  bool terminated = false;
  std::map<u_int, OOOBytes> ooo_queue;
};

/**
 * Our convention: 128-bit key in this order: <source IP, source port,
 * destination IP, destination port>
 */
std::map<__uint128_t, TCPFlowStatus> flow_status_map;

__uint128_t build_map_key(sniff_tcp *tcp, sniff_ip *ip) {
  __uint128_t key = 0;
  key = ip->ip_src.s_addr;                               // 32-bit number
  key = (key << 16) | ((__uint128_t)tcp->th_sport);      // 16-bit number
  key = (key << 32) | ((__uint128_t)ip->ip_dst.s_addr);  // 32-bit number
  key = (key << 16) | ((__uint128_t)tcp->th_dport);      // 16-bit number
  return key;
}

__uint128_t build_peer_map_key(sniff_tcp *tcp, sniff_ip *ip) {
  __uint128_t key = 0;
  key = ip->ip_dst.s_addr;                               // 32-bit number
  key = (key << 16) | ((__uint128_t)tcp->th_dport);      // 16-bit number
  key = (key << 32) | ((__uint128_t)ip->ip_src.s_addr);  // 32-bit number
  key = (key << 16) | ((__uint128_t)tcp->th_sport);      // 16-bit number
  return key;
}

/**
 * Returns the payload contained in the packet. If the packet has no payload, or
 * if the payload is duplicated (for example, a retransmission), returns
 * nullptr. Clients of this function are responsible for freeing the returned
 * pointer, since it is a copy of data passed into the function.
 *
 * The second returned value indicates if the connection has ended. This will
 * only be true when both FINs are seen (both from source and destination). As
 * such, clients of this function should understand that BOTH connections are
 * over in case a true is returned
 *
 * `transport_length` is the packet length starting from tcp header.
 */
std::pair<u_char *, bool> process_packet(sniff_tcp *tcp, sniff_ip *ip,
                                         int transport_length) {
  // beginning of connection
  if ((tcp->th_flags & TH_SYN) &&
      flow_status_map.count(build_map_key(tcp, ip)) == 0) {
    flow_status_map[build_map_key(tcp, ip)] = TCPFlowStatus{
      initial_seqnum : ntohl(tcp->th_seq) + 1,
      received_bytes_count : 0,
      terminated : false
    };
    return {nullptr, false};
  }

  if (!(tcp->th_flags & TH_SYN) &&
      flow_status_map.count(build_map_key(tcp, ip)) == 0) {
    printf("Did not see start of TCP connection\n");
    return {nullptr, false};
  }

  auto &&status = flow_status_map[build_map_key(tcp, ip)];

  // end of connection
  if (tcp->th_flags & TH_FIN) {
    status.terminated = true;
    auto &&peer_status = flow_status_map[build_peer_map_key(tcp, ip)];
    if (peer_status.terminated) {
      flow_status_map.erase(build_map_key(tcp, ip));
      flow_status_map.erase(build_peer_map_key(tcp, ip));
      return {nullptr, true};
    } else {
      return {nullptr, false};
    }
  }

  // mid-connection
  u_int next_seq_num = status.initial_seqnum + status.received_bytes_count;
  if (ntohl(tcp->th_seq) < next_seq_num) {
    return {nullptr, false};  // because this is a retransmission (we already
                              // had this payload)
  }

  // bytes arrived out-of-order
  if (ntohl(tcp->th_seq) > next_seq_num) {
    printf("TCP-streamer queued some out-of-order bytes\n");
    u_int tcp_header_length = get_tcp_header_length(tcp);
    u_int payload_length = transport_length - tcp_header_length;
    if (payload_length == 0) {
      return {nullptr, false};
    }
    u_char *data = new u_char[payload_length];
    memcpy(data, (u_char *)tcp + tcp_header_length, payload_length);
    status.ooo_queue[ntohl(tcp->th_seq)] = OOOBytes{
      begin_seq_num : ntohl(tcp->th_seq),
      next_seq_num : ntohl(tcp->th_seq) + payload_length,
      length : payload_length,
      data : data
    };
    return {nullptr, false};
  }

  // bytes arrived in-order

  // accumulate previous out-of-order bytes
  u_int tcp_header_length = get_tcp_header_length(tcp);
  u_int payload_length = transport_length - tcp_header_length;
  if (payload_length == 0) {
    return {nullptr, false};
  }
  u_int accum_payload_length = payload_length;
  u_int ooo_seq_num = next_seq_num + payload_length;
  u_char *data = new u_char[payload_length];
  memcpy(data, (u_char *)tcp + tcp_header_length, payload_length);
  std::vector<OOOBytes> ooo_recovered;
  ooo_recovered.push_back(OOOBytes{
    begin_seq_num : next_seq_num,
    next_seq_num : ooo_seq_num,
    length : payload_length,
    data : data
  });
  while (status.ooo_queue.count(ooo_seq_num) != 0) {
    auto &&ooo_bytes = status.ooo_queue[ooo_seq_num];
    ooo_recovered.push_back(ooo_bytes);
    ooo_seq_num = ooo_bytes.next_seq_num;
    accum_payload_length += ooo_bytes.length;
  }
  printf("TCP-streamer returned %d consecutive segments\n",
         ooo_recovered.size());
  // accumulate all bytes into single buffer, while freeing old pointer and
  // removing from the map
  u_char *buffer = new u_char[accum_payload_length];
  u_int offset = 0;
  for (auto &&ooo_bytes : ooo_recovered) {
    memcpy(buffer + offset, ooo_bytes.data, ooo_bytes.length);
    offset += ooo_bytes.length;
    delete[] ooo_bytes.data;
    status.ooo_queue.erase(ooo_bytes.begin_seq_num);
  }
  status.received_bytes_count += accum_payload_length;
  return {buffer, false};
}
}  // namespace TCPStreamer

namespace HTTPDefragmenter {

/**
 * Stores information about reassembly status (received headers, received body,
 * etc.) concerning a single
 * source_ip:source_port:destination_ip:destination_port quartet and a single
 * HTTP message
 */
struct MessageReassemblyStatus {
  /**
   * counter for matching \r\n\r\n which characterizes the end of the HTTP
   * headers inside an HTTP message.
   *
   * Thus, this counter goes from 0 to 4. When it gets to 4, this means the
   * headers have finished
   */
  int how_many_terminators_matched = 0;
  int how_many_body_bytes_received = 0;
  /**
   * True if and only if the entire message body has been received (or if the
   * message has no body, in which case the body has trivially been received).
   *
   * As in RFC2616, end of body is detected by:
   *
   * 4.3 Message Body
   *
   *    The message-body (if any) of an HTTP message is used to carry the
   *    entity-body associated with the request or response. The message-body
   *    differs from the entity-body only when a transfer-coding has been
   *    applied, as indicated by the Transfer-Encoding header field (section
   *    14.41).
   *
   *        message-body = entity-body
   *                     | <entity-body encoded as per Transfer-Encoding>
   *
   *    Transfer-Encoding MUST be used to indicate any transfer-codings
   *    applied by an application to ensure safe and proper transfer of the
   *    message. Transfer-Encoding is a property of the message, not of the
   *
   *
   *
   * Fielding, et al.            Standards Track                    [Page 32]
   *
   * RFC 2616                        HTTP/1.1                       June 1999
   *
   *
   *    entity, and thus MAY be added or removed by any application along the
   *    request/response chain. (However, section 3.6 places restrictions on
   *    when certain transfer-codings may be used.)
   *
   *    The rules for when a message-body is allowed in a message differ for
   *    requests and responses.
   *
   *    The presence of a message-body in a request is signaled by the
   *    inclusion of a Content-Length or Transfer-Encoding header field in
   *    the request's message-headers. A message-body MUST NOT be included in
   *    a request if the specification of the request method (section 5.1.1)
   *    does not allow sending an entity-body in requests. A server SHOULD
   *    read and forward a message-body on any request; if the request method
   *    does not include defined semantics for an entity-body, then the
   *    message-body SHOULD be ignored when handling the request.
   *
   *    For response messages, whether or not a message-body is included with
   *    a message is dependent on both the request method and the response
   *    status code (section 6.1.1). All responses to the HEAD request method
   *    MUST NOT include a message-body, even though the presence of entity-
   *    header fields might lead one to believe they do. All 1xx
   *    (informational), 204 (no content), and 304 (not modified) responses
   *    MUST NOT include a message-body. All other responses do include a
   *    message-body, although it MAY be of zero length.
   *
   * 4.4 Message Length
   *
   *    The transfer-length of a message is the length of the message-body as
   *    it appears in the message; that is, after any transfer-codings have
   *    been applied. When a message-body is included with a message, the
   *    transfer-length of that body is determined by one of the following
   *    (in order of precedence):
   *
   *    1.Any response message which "MUST NOT" include a message-body (such
   *      as the 1xx, 204, and 304 responses and any response to a HEAD
   *      request) is always terminated by the first empty line after the
   *      header fields, regardless of the entity-header fields present in
   *      the message.
   *
   *    2.If a Transfer-Encoding header field (section 14.41) is present and
   *      has any value other than "identity", then the transfer-length is
   *      defined by use of the "chunked" transfer-coding (section 3.6),
   *      unless the message is terminated by closing the connection.
   *
   *    3.If a Content-Length header field (section 14.13) is present, its
   *      decimal value in OCTETs represents both the entity-length and the
   *      transfer-length. The Content-Length header field MUST NOT be sent
   *      if these two lengths are different (i.e., if a Transfer-Encoding
   *
   *
   *
   * Fielding, et al.            Standards Track                    [Page 33]
   *
   * RFC 2616                        HTTP/1.1                       June 1999
   *
   *
   *      header field is present). If a message is received with both a
   *      Transfer-Encoding header field and a Content-Length header field,
   *      the latter MUST be ignored.
   *
   *    4.If the message uses the media type "multipart/byteranges", and the
   *      ransfer-length is not otherwise specified, then this self-
   *      elimiting media type defines the transfer-length. This media type
   *      UST NOT be used unless the sender knows that the recipient can arse
   *      it; the presence in a request of a Range header with ultiple byte-
   *      range specifiers from a 1.1 client implies that the lient can parse
   *      multipart/byteranges responses.
   *
   *        A range header might be forwarded by a 1.0 proxy that does not
   *        understand multipart/byteranges; in this case the server MUST
   *        delimit the message using methods defined in items 1,3 or 5 of
   *        this section.
   *
   *    5.By the server closing the connection. (Closing the connection
   *      cannot be used to indicate the end of a request body, since that
   *      would leave no possibility for the server to send back a response.)
   *
   *    For compatibility with HTTP/1.0 applications, HTTP/1.1 requests
   *    containing a message-body MUST include a valid Content-Length header
   *    field unless the server is known to be HTTP/1.1 compliant. If a
   *    request contains a message-body and a Content-Length is not given,
   *    the server SHOULD respond with 400 (bad request) if it cannot
   *    determine the length of the message, or with 411 (length required) if
   *    it wishes to insist on receiving a valid Content-Length.
   *
   *    All HTTP/1.1 applications that receive entities MUST accept the
   *    "chunked" transfer-coding (section 3.6), thus allowing this mechanism
   *    to be used for messages when the message length cannot be determined
   *    in advance.
   *
   *    Messages MUST NOT include both a Content-Length header field and a
   *    non-identity transfer-coding. If the message does include a non-
   *    identity transfer-coding, the Content-Length MUST be ignored.
   *
   *    When a Content-Length is given in a message where a message-body is
   *    allowed, its field value MUST exactly match the number of OCTETs in
   *    the message-body. HTTP/1.1 user agents MUST notify the user when an
   *    invalid length is received and detected.
   */
  bool message_body_terminated = false;
  /**
   * Bytes left unparsed since the last call to assemble was made.
   * For example, `leftover_data` can contain the start of a message header
   * which, for some reason, came in separate packets.
   *
   * As another example, `leftover_data` can contain parts of the message body
   * while it is not completely received.
   */
  u_char *leftover_data = nullptr;
  int leftover_data_length = 0;
};

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
    printf("tcp_seq_num=%u ", ntohl(tcp->th_seq));
    printf("tcp_s_port=%u ", ntohs(tcp->th_sport));
    printf("tcp_d_port=%u ", ntohs(tcp->th_dport));
    u_char *payload = data + ip_header_length + tcp_header_length;
    printf("Payload data:\n(%.*s)\n\n", payload_length, payload);

    IPDefragmenter::Packet *reassemble =
        IPDefragmenter::defrag((u_char *)ip, ret);

    if (reassemble != nullptr) {
      tcp = (sniff_tcp *)reassemble->data;
      tcp_header_length = get_tcp_header_length(tcp);
      payload_length = reassemble->length - tcp_header_length;
      payload = reassemble->data + tcp_header_length;
      printf("Just IP-Reassembled packet:\n(%.*s)\n\n", payload_length,
             payload);
      std::pair<u_char *, bool> tcp_dedup =
          TCPStreamer::process_packet(tcp, ip, reassemble->length);
      if (tcp_dedup.second) {
        printf("Reassembled has TCP ended\n");
      }
      if (tcp_dedup.first) {
        printf("Reassembled TCP payload:\n(%.*s)\n\n", payload_length,
               tcp_dedup.first);
        delete[] tcp_dedup.first;
      }
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