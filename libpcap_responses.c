/* ldev.c
 *    Martin Casado
 *       
 *          To compile:
 *             >gcc ldev.c -lpcap
 *
 *                Looks for an interface, and lists the network ip
 *                   and mask associated with that interface.
 *                   */
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
#include <dirent.h>

#define IN6ADDR "DEAD:BEEF:7654:3210:FEDC:3210:7654:BA98"

struct capture_info {
    int total_pkt_count;
    int echo_req_count;
    int echo_reply_count;
    int time_exceeded_count;
    int no_route_count;
    int address_unreachable_count;
    int admin_prohibited_count;
    int port_unreachable_count;
    int reject_route_count;
    int failed_policy_count;
};


void print_packet_info(u_char *info, const u_char *packet, struct pcap_pkthdr packet_header) {
  //printf("Packet capture length: %d\n", packet_header.caplen);
  //printf("Packet total length %d\n", packet_header.len);
  //struct pcap_pkthdr pcap_header;
  struct ether_header *eth_header;
  //struct ethhdr *eth_h = (struct ethhdr*) packet;
  //const u_char *ipv6_header;
  int ipv6_header_length;
  struct ip6_hdr *ipv6_header;
  struct icmp6_hdr *icmpv6_header;
  //struct ip6_hdr *ipv6_header2;
  /* The packet is larger than the ether_header struct,
   * but we just want to look at the first part of the packet
   * that contains the header. We force the compiler
   * to treat the pointer to the packet as just a pointer
   * to the ether_header. The data payload of the packet comes
   * after the headers. Different packet types have different header
   * lengths though, but the ethernet header is always the same (14 bytes) */
  eth_header = (struct ether_header *) packet;
  //ethernet header length == 14
  //ipv6_header2 = (struct ip6_hdr *) packet + 14;
  //ipv6_header = (struct ip6_hdr *) packet + sizeof(struct ethhdr);
  ipv6_header = packet + sizeof(struct ether_header);
  //ipv6_header = (struct ip6_hdr *) packet + sizeof(struct ether_header);
  icmpv6_header = packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr);
  //ipv6_header_length = ((*ipv6_header) & )
  //struct in6_addr *ipv6_addr;
  char buf6[INET6_ADDRSTRLEN];
  //struct in6_addr in6addr;

  //inet_pton(AF_INET6, ipv6_hdr->ip6_dst, &in6addr);
  //inet_pton(AF_INET6, (ipv6_header + 64), &in6addr);
  struct capture_info *i;
  i = (struct capture_info *) info;
  //i->total_pkt_count++;
  //i->echo_req_count++;
      

  if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
    printf("IP\n");
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
    printf("ARP\n");
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP) {
    printf("Reverse ARP\n");
  //} else if (ntohl(eth_h->h_proto) == ETH_P_IPV6) {
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
      //ICMPv6 payload
      if (ipv6_header->ip6_nxt == 58) {
	//printf("ICMPv6\n");
	//printf("type: %d, ", icmpv6_header->icmp6_type);
	//Check for Echo Request
	if (icmpv6_header->icmp6_type == 128){
	  //printf("Echo Req\n");
	  i->echo_req_count++;
          i->total_pkt_count++;
	//Check for Echo Reply
	} else if (icmpv6_header->icmp6_type == 129){
	  //printf("Echo Reply\n");
	  i->echo_reply_count++; 
          i->total_pkt_count++;
	//Check for Time Exceeded
	} else if (icmpv6_header->icmp6_type == 3){
	  //printf("Time Exceeded\n");
	  i->time_exceeded_count++;
	  i->total_pkt_count++;
	//Check for Destination Unreachable
	} else if (icmpv6_header->icmp6_type == 1){
	    //No Route
	    if (icmpv6_header->icmp6_code == 0){
	       i->no_route_count++;
	    //Address Unreachable
	    } else if (icmpv6_header->icmp6_code == 3){
	       i->address_unreachable_count++;
	    //Communication with destination administratively prohibited
            } else if (icmpv6_header->icmp6_code == 1){
	       i->admin_prohibited_count++;
	    //Port Unreachable
            } else if (icmpv6_header->icmp6_code == 4){
	       i->port_unreachable_count++;
	    //Reject Route to Destination
            } else if (icmpv6_header->icmp6_code == 6){
	       i->reject_route_count++;
	    //Failed Ingress/Egress Policy
            } else if (icmpv6_header->icmp6_code == 5){
	       i->failed_policy_count++;
            } else {
	       printf("Unhandled ICMPv6 unreachable code: %d\n", icmpv6_header->icmp6_code);
	    }
	    i->total_pkt_count++;
	//Neighbour Solicitation - ignore
	} else if (icmpv6_header->icmp6_type == 135){
		;
	//Neighbour Advertisement - ignore
	} else if (icmpv6_header->icmp6_type == 136){
		;
	} else {
	  printf("type: %d\n", icmpv6_header->icmp6_type);
	}
      }
    //printf("Other, ip6_nxt: %d\n", ipv6_header->ip6_nxt);}
    //printf("IPv6\n");
    //printf("ether_type: %x\n", ntohs(eth_header->ether_type));
    //printf("sizeof: %ld\n", sizeof(struct ether_header));
    //printf("eth_header: %p, ipv6_header: %p\n", eth_header, ipv6_header);
  }

   
  //char buf6[INET6_ADDRSTRLEN];
  //struct in6_addr in6addr;
  //inet_pton(AF_INET6, IN6ADDR, &in6addr);
  //if (ntohs(ipv6_header->))
  
  //printf("hl: %d\n", ntohs(ipv6_header->ip6_hlim));
  //uint32_t ipv6_fl = ntohl(ipv6_header->ip6_flow);
  //printf("Flow label for this packet: 0x%x\n", ipv6_fl);

  //printf("\ndst: %s\n", inet_ntop(AF_INET6, &ipv6_header->ip6_dst, buf6, sizeof(buf6)));
  //printf("src: %s\n", inet_ntop(AF_INET6, &ipv6_header->ip6_src, buf6, sizeof(buf6)));
  //printf("next: %d\n", ipv6_header->ip6_nxt);
  //printf("hops: %d\n", ipv6_header->ip6_hops);
  //const char* dst = inet_ntop(AF_INET6, &ipv6_header->ip6_dst, buf6, sizeof(buf6));
  //printf("assigned dst: %s\n", dst);

}


void my_packet_handler(u_char *info, const struct pcap_pkthdr *packet_header, const u_char *packet_body){
  print_packet_info(info, packet_body, *packet_header);
}

int dir_loop(char *dirname, struct capture_info *info){
  DIR *folder;
  struct dirent *entry;
  int count = 0;
  char error_buffer[PCAP_ERRBUF_SIZE];
  const u_char *packet;
  struct pcap_pkthdr packet_header;
  pcap_t *handle = NULL;
  char abs_path[256];

  folder = opendir(dirname);
  if (folder == NULL){
    perror("Can't read directory.\n");
    return(1);
  }

  //TODO: these checks to skip . and .. are janky as hell, change to something better
  while((entry=readdir(folder))){
    if (strcmp(entry->d_name, ".")){
      if (strcmp(entry->d_name, "..")){
        count++;
        //printf("File %d: %s\n", count, entry->d_name);
	strcpy(abs_path, dirname);
	strcat(abs_path, "/");
	strcat(abs_path, entry->d_name);
	//printf("Absolute: %s\n", abs_path);
        handle = pcap_open_offline(abs_path, error_buffer);
	pcap_loop(handle, 0, my_packet_handler, (u_char*)info);
	//printf("Loop done.\n");
	/*
	printf(
	  "Ongoing count:\nEcho Req: %d\nEcho Reply: %d\nTime Exceeded: %d\nNo Route: %d\nAddress Unreachable: %d\nAdmin Prohibited: %d\nPort Unreachable: %d\nReject Route: %d\nSrc Addr Failed Ingress/Egress Policy: %d\nTotal: %d\n\n", 
	  info->echo_req_count, info->echo_reply_count, info->time_exceeded_count, info->no_route_count, 
	  info->address_unreachable_count, info->admin_prohibited_count, info->port_unreachable_count, 
	  info->reject_route_count, info->failed_policy_count, info->total_pkt_count);
	*/
        	
      } else {
        //printf("Skipping file %s\n", entry->d_name);
      }
    } else {
      //printf("Skipping file %s\n", entry->d_name);
    }
  }

  closedir(folder);
  return(0);
}


int main(int argc, char **argv)
{
  char *dev; /* name of the device to use */ 
  char *net; /* dot notation of the network address */
  char *mask;/* dot notation of the network mask    */
  int ret;   /* return code */
  //char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 netp; /* ip          */
  bpf_u_int32 maskp;/* subnet mask */
  struct in_addr addr;
  char error_buffer[PCAP_ERRBUF_SIZE];
  //pcap_t *handle = pcap_open_offline("/home/vivian/13-10-2021-send-1000lines.pcap", error_buffer);
  //pcap_t *handle = pcap_open_offline("1000-items.pcap", error_buffer);
  const u_char *packet;
  struct pcap_pkthdr packet_header;

  //dir_loop(argv[1]);

  /* ask pcap to find a valid device for use to sniff on */
  dev = pcap_lookupdev(error_buffer);

  /* error checking */
  if(dev == NULL)
  {
   //printf("%s\n",error_buffer);
   exit(1);
  }

  /* print out device name */
  //printf("DEV: %s\n",dev);

  /* ask pcap for the network address and mask of the device */
  ret = pcap_lookupnet(dev,&netp,&maskp,error_buffer);

  if(ret == -1)
  {
   printf("%s\n",error_buffer);
   exit(1);
  }

  /* get the network address in a human readable form */
  addr.s_addr = netp;
  net = inet_ntoa(addr);

  if(net == NULL)/* thanks Scott :-P */
  {
   perror("inet_ntoa");
   exit(1);
  }

  //printf("NET: %s\n",net);

  /* do the same as above for the device's mask */
  addr.s_addr = maskp;
  mask = inet_ntoa(addr);
					
  if(mask == NULL)
  {
   perror("inet_ntoa");
   exit(1);
  }
					  
  //printf("MASK: %s\n",mask);
  
/*  
  packet = pcap_next(handle, &packet_header);
  if (packet == NULL) {
     printf("No packet found.\n");
  } else {
     printf("Packet found.\n");
  }
*/

  struct capture_info info;
  info.total_pkt_count = 0;
  info.echo_req_count = 0;
  info.echo_reply_count = 0;
  info.time_exceeded_count = 0;
  info.no_route_count = 0;
  info.address_unreachable_count = 0;
  info.admin_prohibited_count = 0;
  info.port_unreachable_count = 0;
  info.reject_route_count = 0;
  info.failed_policy_count = 0;
 
  dir_loop(argv[1], &info);

  //pcap_loop(handle, 0, my_packet_handler, (u_char*)&info);

  printf("final count: %d\n", info.total_pkt_count);
  printf("final req count: %d\n", info.echo_req_count);
  printf("final reply count: %d\n", info.echo_reply_count);
  printf("final time exceeded count: %d\n", info.time_exceeded_count);
  printf("final no route count: %d\n", info.no_route_count);
  printf("final address unreachable count: %d\n", info.address_unreachable_count);
  printf("final admin prohibited count: %d\n", info.admin_prohibited_count);
  printf("final port unreachable count: %d\n", info.port_unreachable_count);
  printf("final reject route count: %d\n", info.reject_route_count);
  printf("final failed policy count: %d\n", info.failed_policy_count);
  return 0;
}



