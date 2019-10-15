/**
 * Shamelessly adapted from https://www.devdungeon.com/content/using-libpcap-c
 *
 */

#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdio.h>
#include <time.h>

/**
 * Taken shamelessly from https://www.tcpdump.org/pcap.html
 */
/* Ethernet addresses are 6 bytes */
// #define ETHER_ADDR_LEN 6

#define SIZE_ETHERNET 14

/* Ethernet header */
struct sniff_ethernet {
  u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
  u_short ether_type;                 /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
  u_char ip_vhl;                 /* version << 4 | header length >> 2 */
  u_char ip_tos;                 /* type of service */
  u_short ip_len;                /* total length */
  u_short ip_id;                 /* identification */
  u_short ip_off;                /* fragment offset field */
#define IP_RF 0x8000             /* reserved fragment flag */
#define IP_DF 0x4000             /* dont fragment flag */
#define IP_MF 0x2000             /* more fragments flag */
#define IP_OFFMASK 0x1fff        /* mask for fragmenting bits */
  u_char ip_ttl;                 /* time to live */
  u_char ip_p;                   /* protocol */
  u_short ip_sum;                /* checksum */
  struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
  u_short th_sport; /* source port */
  u_short th_dport; /* destination port */
  tcp_seq th_seq;   /* sequence number */
  tcp_seq th_ack;   /* acknowledgement number */
  u_char th_offx2;  /* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
  u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
  u_short th_win; /* window */
  u_short th_sum; /* checksum */
  u_short th_urp; /* urgent pointer */
};

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