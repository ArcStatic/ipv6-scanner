#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <linux/if_ether.h>
#include <inttypes.h>

#define BUFSIZE 48

int main(int argc, char** argv){

    struct sockaddr_in6 dst_sockaddr;
    char pkt_buffer[BUFSIZE];
    size_t pkt_len = sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);
    struct ip6_hdr *ipv6_header;
    struct icmp6_hdr *icmpv6_header;
    int sock;
    struct in6_addr dst_addr;
    char *dst_str = argv[2];
    char *src_str = argv[1];

    memset(pkt_buffer, 0, BUFSIZE);
    sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    //sock = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
    

    if (sock < 0) {
	perror("Error creating socket.\n");
	return 0;
    }

    ipv6_header = (struct ip6_hdr*) (pkt_buffer);
    icmpv6_header = (struct icmp6_hdr*) (pkt_buffer + sizeof(struct ip6_hdr));


    //ipv6_header->ip6_ctlun.ip6_un2_vfc = ;
    //ipv6_header->ip6_vfc = 70;
    //ipv6_header->ip6_vfc = 6 << 4;
    //ipv6_header->ip6_dst = inet_pton(AF_INET6, dst_str, &(ip6));
    inet_pton(AF_INET6, dst_str, &(ipv6_header->ip6_dst));
    inet_pton(AF_INET6, src_str, &(ipv6_header->ip6_src));
    //set IP version to 6 (uint32_t, version is upper 4 bits)
    ipv6_header->ip6_flow = 6 << 28;
    //ipv6_header->ip6_hops = 0;
    ipv6_header->ip6_hlim = 255;
    //58: next header ICMPv6
    ipv6_header->ip6_nxt = 58;
    //8 byte payload length for ICMPv6 Echo Request
    ipv6_header->ip6_plen = 8;
    
    //type 128 for Echo Request, code value 0
    icmpv6_header->icmp6_type = 128;
    icmpv6_header->icmp6_code = 0;

    memset(&dst_sockaddr, 0, sizeof(dst_sockaddr));
    dst_sockaddr.sin6_family = AF_INET6;
    //arbitrarily chosen, not needed for ICMPv6
    dst_sockaddr.sin6_port = htons(10000);
    inet_pton(AF_INET6, dst_str, &(dst_sockaddr.sin6_addr));

    if (sendto(sock, pkt_buffer, pkt_len, 0, (struct sockaddr *) &dst_sockaddr, sizeof(struct sockaddr)) == -1){
        printf("Error: %s, %d\n", strerror(errno), errno);
    } else {
        printf("Sent!\n");
    }


    
    /* all debug stuff, output is as expected

    char buf6[INET6_ADDRSTRLEN];
    struct in6_addr in6addr;
    const char* dst = inet_ntop(AF_INET6, &ipv6_header->ip6_dst, buf6, sizeof(buf6)); 
    printf("assigned dst: %s\n", dst);
    const char* src = inet_ntop(AF_INET6, &ipv6_header->ip6_src, buf6, sizeof(buf6)); 
    printf("assigned src: %s\n", src);
    const char* dst_s = inet_ntop(AF_INET6, &(dst_sockaddr.sin6_addr), buf6, sizeof(buf6)); 
    printf("assigned dst sockaddr: %s\n", dst_s);

    printf("pkt buffer:    %p\nlen: %ld\n", ipv6_header, sizeof(pkt_buffer)); 
    printf("ipv6 header: %p\nlen: %ld\n", ipv6_header, sizeof(struct ip6_hdr)); 
    printf("icmpv6 header: %p\nlen: %ld\n", icmpv6_header, sizeof(struct icmp6_hdr));
    printf("sockaddr: %p\nlen: %ld\n", &dst_sockaddr, sizeof(struct sockaddr));
    printf("sockaddr_in6: %p\nlen: %ld\n", &dst_sockaddr, sizeof(struct sockaddr_in6));
    printf("sock: %d\n", sock);
    printf("buff: %d\n", pkt_buffer[0]);
    printf("pkt_len: %ld\n", pkt_len);
    printf("ipv6_header vfc: %" PRIu8 "\n", ipv6_header->ip6_vfc);
    printf("ipv6_header version (vfc): %" PRIu8 "\n", (ipv6_header->ip6_vfc) >> 4);   
    printf("ipv6_header version (flow): %" PRIu32 "\n", (ipv6_header->ip6_flow) >> 28);
    printf("ipv6_header flow: %" PRIu32 "\n", ipv6_header->ip6_flow);
    printf("ipv6_header plen: %" PRIu16 "\n", ipv6_header->ip6_plen);
    printf("ipv6_header nxt: %" PRIu8 "\n", ipv6_header->ip6_nxt);
    printf("ipv6_header hl: %" PRIu8 "\n", ipv6_header->ip6_hops);
    printf("ipv6_header hl: %u\n", ipv6_header->ip6_hlim);
    printf("ipv6_header nh: %u\n", *(pkt_buffer + 6));
    printf("ipv6_header paylen: %u\n", *(pkt_buffer + 4));
    printf("icmpv6_header type: %u\n", icmpv6_header->icmp6_type);
    printf("icmpv6_header code: %u\n", icmpv6_header->icmp6_code);
    */

}
