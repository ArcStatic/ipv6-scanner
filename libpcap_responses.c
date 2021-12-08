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

#define PFX_STR_SIZE 15

struct capture_info {
    int total_resp_count;
    int echo_req_count;
    int echo_reply_count;
    int time_exceeded_count;
    int no_route_count;
    int address_unreachable_count;
    int admin_prohibited_count;
    int port_unreachable_count;
    int reject_route_count;
    int failed_policy_count;
    struct pfx* current_pfx;
};

struct pfx {
    char* pfx_addr;
    int mask_len;
    struct capture_info* info;
    struct pfx* next;
    struct pfx* prev;
};


void print_packet_info(u_char *info, const u_char *packet, struct pcap_pkthdr packet_header) {
  struct ether_header *eth_header;
  int ipv6_header_length;
  struct ip6_hdr *ipv6_header;
  struct icmp6_hdr *icmpv6_header;
  eth_header = (struct ether_header *) packet;
  ipv6_header = packet + sizeof(struct ether_header);
  icmpv6_header = packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr);

  struct capture_info *i;
  i = (struct capture_info *) info;

  char ipv6_addr_str[100];
  char ipv6_str_slice[15];

  if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
    printf("IP\n");
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
    printf("ARP\n");
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP) {
    printf("Reverse ARP\n");
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
      //ICMPv6 payload
      if (ipv6_header->ip6_nxt == 58) {
        inet_ntop(AF_INET6, &ipv6_header->ip6_src, ipv6_addr_str, 100);
        //inet_ntop(AF_INET6, &ipv6_header->ip6_src, ipv6_str_slice, 100);
        printf("Addr: %s\n", ipv6_addr_str);
	memcpy(ipv6_str_slice, ipv6_addr_str, 14);
	ipv6_str_slice[15] = '\0';
	//why is this call blank after memcpy?
        //printf("Addr: %s\n", ipv6_addr_str);
        if (i->current_pfx->pfx_addr == NULL){
	  //
	  i->current_pfx->pfx_addr = (char*) malloc(PFX_STR_SIZE);
	  strcpy(i->current_pfx->pfx_addr, ipv6_str_slice);
	} else if (strcmp(i->current_pfx->pfx_addr, ipv6_str_slice) != 0){
	//} else if (i->current_pfx->pfx_addr != *(ipv6_str_slice)){
	  strcpy(i->current_pfx->pfx_addr, ipv6_str_slice);
	}	
        printf("Slice: %s\n", i->current_pfx->pfx_addr);
        printf("Str slice: %s\n", ipv6_str_slice);

//printf("ICMPv6\n");
	//printf("type: %d, ", icmpv6_header->icmp6_type);
	//Check for Echo Request
	if (icmpv6_header->icmp6_type == 128){
	  //printf("Echo Req\n");
	  i->echo_req_count++;
	  //not a response, this is an outgoing probe
          //i->total_resp_count++;
	//Check for Echo Reply
	} else if (icmpv6_header->icmp6_type == 129){
	  //printf("Echo Reply\n");
	  i->echo_reply_count++; 
          i->total_resp_count++;
	//Check for Time Exceeded
	} else if (icmpv6_header->icmp6_type == 3){
	  //printf("Time Exceeded\n");
	  i->time_exceeded_count++;
	  i->total_resp_count++;
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
	    i->total_resp_count++;
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
  }
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
  struct pfx *current_pfx;

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
	  "Ongoing count:\nEcho Req: %d\nEcho Reply: %d\nTime Exceeded: %d\nNo Route: %d\nAddress Unreachable: %d\nAdmin Prohibited: %d\nPort Unreachable: %d\nReject Route: %d\nSrc Addr Failed Ingress/Egress Policy: %d\nTotal responses: %d\n\n", 
	  info->echo_req_count, info->echo_reply_count, info->time_exceeded_count, info->no_route_count, 
	  info->address_unreachable_count, info->admin_prohibited_count, info->port_unreachable_count, 
	  info->reject_route_count, info->failed_policy_count, info->total_resp_count);
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
  struct capture_info info;
  info.total_resp_count = 0;
  info.echo_req_count = 0;
  info.echo_reply_count = 0;
  info.time_exceeded_count = 0;
  info.no_route_count = 0;
  info.address_unreachable_count = 0;
  info.admin_prohibited_count = 0;
  info.port_unreachable_count = 0;
  info.reject_route_count = 0;
  info.failed_policy_count = 0;
 
  struct pfx* current_pfx;

  current_pfx = (struct pfx*)malloc(sizeof(struct pfx));
  current_pfx->pfx_addr = NULL;
  current_pfx->mask_len = 0;
  current_pfx->prev = NULL;
  current_pfx->next = NULL;
  current_pfx->info = (struct capture_info*)malloc(sizeof(struct capture_info));

  info.current_pfx = current_pfx;
  
  //populate info struct with data from both send and receive captures:
  for (int i = 1; i <= argc - 1; i++){
    if (strstr(argv[i], "send") != NULL){
	//printf("Send dir: %s\n", argv[i]);
        dir_loop(argv[i], &info);
    } else if (strstr(argv[i], "recv") != NULL){
	//printf("Recv dir: %s\n", argv[i]);
	dir_loop(argv[i], &info);
    }
  }
  
  
  
  printf(
	  "Ongoing count:\nEcho Req: %d\nEcho Reply: %d\nTime Exceeded: %d\nNo Route: %d\nAddress Unreachable: %d\nAdmin Prohibited: %d\nPort Unreachable: %d\nReject Route: %d\nSrc Addr Failed Ingress/Egress Policy: %d\nTotal responses received: %d\n\n", 
	  info.echo_req_count, info.echo_reply_count, info.time_exceeded_count, info.no_route_count, 
	  info.address_unreachable_count, info.admin_prohibited_count, info.port_unreachable_count, 
	  info.reject_route_count, info.failed_policy_count, info.total_resp_count
  );


  return 0;
}



