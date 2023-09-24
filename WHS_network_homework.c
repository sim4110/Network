#include <stdio.h>
#include <pcap.h>
#include <netinet/tcp.h>

struct ether_hdr {
    unsigned char ether_dhost[6]; // destination MAC address
    unsigned char ether_shost[6]; // source host address
    unsigned short ether_type;    // protocol type(IP, ARP, etc)
};

struct ip_hdr {
    unsigned char ip_vhl;         // IP header length and version
    unsigned char ip_tos;         // Type of service
    unsigned short ip_len;        // IP Packet length(data + header)
    unsigned short ip_id;         // Identification
    unsigned short ip_off;        // Fragemntation flags and offset
    unsigned char ip_ttl;         // Time-to-Live (TTL)
    unsigned char ip_protocol;    // Protocol type
    unsigned short ip_chksum;     // IP datagram chcksum 
    unsigned int ip_src;          // source IP address
    unsigned int ip_dst;          // destination IP address
};

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {

    struct ether_hdr *eth_header;
    struct ip_hdr *ip_header;
    struct tcphdr *tcp_header;

    eth_header = (struct ether_hdr *)packet;
    ip_header = (struct ip_hdr *)(packet + sizeof(struct ether_hdr));
    printf("\n");

    if (ntohs(eth_header->ether_type) == 0x0800) {
        printf("Packet captured. Length: %d\n", pkthdr->len);

        printf("Ethernet src MAC : %02X:%02X:%02X:%02X:%02X:%02X\n",
                eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2],
                eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
        printf("Ethernet dst MAC : %02X:%02X:%02X:%02X:%02X:%02X\n",
                eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2],
                eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

        printf("IP src : %u.%u.%u.%u\n",
      	        (ntohl(ip_header->ip_src) >> 24) & 0xFF, (ntohl(ip_header->ip_src) >> 16) & 0xFF,
      	        (ntohl(ip_header->ip_src) >> 8) & 0xFF, ntohl(ip_header->ip_src) & 0xFF);
	    printf("IP dst : %u.%u.%u.%u\n",
       	        (ntohl(ip_header->ip_dst) >> 24) & 0xFF, (ntohl(ip_header->ip_dst) >> 16) & 0xFF,
      	        (ntohl(ip_header->ip_dst) >> 8) & 0xFF, ntohl(ip_header->ip_dst) & 0xFF);
	
        if (ip_header->ip_protocol == IPPROTO_TCP) {
            tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_hdr) + ((ip_header->ip_vhl & 0x0F) << 2));

            printf("TCP src Port: %u\n", ntohs(tcp_header->th_sport));
            printf("TCP dst Port: %u\n", ntohs(tcp_header->th_dport));
        }
            printf("=============================");

    }
}

int main() {
    char *dev = "ens33"; 

    printf("network Dev %s\n", dev);

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error: %s\n", errbuf);
        return 1;
    }

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);

    return 0;
}