/**
 * Shamelessly adapted from https://www.devdungeon.com/content/using-libpcap-c
 *
 */

#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdio.h>
#include <time.h>

#include "packet_structs.h"

/* signature of sniffer function */
void my_packet_handler(u_char *args, const struct pcap_pkthdr *header,
                       const u_char *packet);

int main(int argc, char *argv[]) {
  char *device;
  char error_buffer[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  int timeout_limit = 10000; /* In milliseconds */

  device = pcap_lookupdev(error_buffer);
  if (device == NULL) {
    printf("Error finding device: %s\n", error_buffer);
    return 1;
  }

  /* Open device for live capture */
  handle = pcap_open_live(device, /* BUFSIZ */ 64 * 1024, 0, timeout_limit,
                          error_buffer);
  if (handle == NULL) {
    fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
    return 2;
  }

  pcap_loop(handle, 0, my_packet_handler, NULL);

  return 0;
}

/* Finds the payload of a TCP/IP packet */
void my_packet_handler(u_char *args, const struct pcap_pkthdr *header,
                       const u_char *packet) {
  sniff_ethernet *ethernet;
  sniff_ip *ip;
  sniff_tcp *tcp;
  /* First, lets make sure we have an IP packet */
  ethernet = (sniff_ethernet *)packet;
  if (ntohs(ethernet->ether_type) != ETHERTYPE_IP) {
    printf("Not an IP packet. Skipping...\n\n");
    return;
  }

  /* The total packet length, including all headers
     and the data payload is stored in
     header->len and header->caplen. Caplen is
     the amount actually available, and len is the
     total packet length even if it is larger
     than what we currently have captured. If the snapshot
     length set with pcap_open_live() is too small, you may
     not have the whole packet. */
  printf("Total packet available: %d bytes\n", header->caplen);
  printf("Expected packet size: %d bytes\n", header->len);

  /* Pointers to start point of various headers */
  const u_char *ip_header;
  const u_char *tcp_header;
  const u_char *payload;

  /* Header lengths in bytes */
  int ethernet_header_length = 14; /* Doesn't change */
  int ip_header_length;
  int tcp_header_length;
  int payload_length;

  /* Find start of IP header */
  ip = (sniff_ip *)(packet + SIZE_ETHERNET);
  /* The IHL is number of 32-bit segments. Multiply
     by four to get a byte count for pointer arithmetic */
  ip_header_length = IP_HL(ip) * 4;
  if (ip_header_length < 20) {
    printf("   * Invalid IP header length: %u bytes\n", ip_header_length);
    return;
  }
  printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

  /* Now that we know where the IP header is, we can
     inspect the IP header for a protocol number to
     make sure it is TCP before going any further.
     Protocol is always the 10th byte of the IP header */
  if (ip->ip_p != IPPROTO_TCP) {
    printf("Not a TCP packet. Skipping...\n\n");
    return;
  }

  /* Add the ethernet and ip header length to the start of the packet
     to find the beginning of the TCP header */
  tcp = (sniff_tcp *)(packet + SIZE_ETHERNET + ip_header_length);
  printf("TCP seq number: %u\n", tcp->th_seq);
  printf("TCP ack number: %u\n", tcp->th_ack);
  /* The TCP header length stored in those 4 bits represents
     how many 32-bit words there are in the header, just like
     the IP header length. We multiply by four again to get a
     byte count. */
  tcp_header_length = TH_OFF(tcp) * 4;
  printf("TCP header length in bytes: %d\n", tcp_header_length);

  /* Add up all the header sizes to find the payload offset */
  int total_headers_size =
      ethernet_header_length + ip_header_length + tcp_header_length;
  printf("Size of all headers combined: %d bytes\n", total_headers_size);
  payload_length = header->caplen - (ethernet_header_length + ip_header_length +
                                     tcp_header_length);
  printf("Payload size: %d bytes\n", payload_length);
  payload = packet + total_headers_size;
  printf("Memory address where payload begins: %p\n", payload);
  printf("Payload data:\n(%.*s)\n\n", payload_length, payload);

  /* Print payload in ASCII */
  /*
  if (payload_length > 0) {
      const u_char *temp_pointer = payload;
      int byte_count = 0;
      while (byte_count++ < payload_length) {
          printf("%c", *temp_pointer);
          temp_pointer++;
      }
      printf("\n");
  }
  */

  return;
}