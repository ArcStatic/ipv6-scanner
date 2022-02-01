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
#include <unistd.h>

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
    struct addr_byte_node* addr_tree_root;
};

struct pfx {
    char* pfx_addr;
    int mask_len;
    struct capture_info* info;
    struct pfx* next;
    struct pfx* prev;
};

struct addr_byte_node {
    unsigned char bit_val;
    struct addr_byte_node* parent;
    int desc_count;
    char* icmpv6_msg;
    struct addr_byte_node* descendents;
    struct addr_byte_node* next;
    struct addr_byte_node* prev;
};

void trace_addr_path(struct addr_byte_node* current_node, struct ip6_hdr* ipv6_header, struct icmp6_hdr* icmpv6_header, char* icmpv6_msg_str){
	
        //struct icmp6_hdr *icmpv6_header;
	unsigned int oct_val;
	struct addr_byte_node* new_desc;
	char* icmpv6_str;
	char* icmpv6_err_target;
	char ip6_addr_str[50];
	char ip6_err_addr_str[50];
	
	icmpv6_header = (struct icmp6_hdr*) (ipv6_header + 1);
	oct_val = 0;
	icmpv6_str = NULL;

	//printf("func: ip6: %p, icmp6: %p\n", ipv6_header, icmpv6_header);
	//trace tree path for IPv6 address
	//printf("\n\nSTART PATH TRACE\n");
	//step through each byte of IPv6 network prefix (ie. 8 bytes)
	
	//TODO: remote soon, echo reply testing only
	//if (icmpv6_header->icmp6_type == 129){
	
        //sleep(1);

	for (int ip6_byte = 0; ip6_byte < 8; ip6_byte++){
	  //for Echo Reply, dst field is the same as the intended probe target
	  if (icmpv6_header->icmp6_type == 129){
  	    oct_val = ipv6_header->ip6_src.s6_addr[ip6_byte];
	    //printf("i: %d, oct val: %d\n", ip6_byte, oct_val);
	    if (ip6_byte == 0){
	      printf("Reply sender: %s\n", inet_ntop(AF_INET6, &ipv6_header->ip6_src.s6_addr, ip6_addr_str, 50));
	    }
	  } else {
	  //For ICMPv6 error messages, the sender is not the intended target
	  //path followed through the tree should be for the intended target, not the middlebox sender
	    oct_val = icmpv6_header->icmp6_data8[ip6_byte];
	    //recover original target dst from ICMPv6 payload
            icmpv6_err_target = (char*) &(icmpv6_header->icmp6_data8) + 28;
  	    oct_val = (unsigned int) icmpv6_err_target[ip6_byte];
            //printf("Error target: %s\n", inet_ntop(AF_INET6, icmpv6_err_target, ip6_addr_str, 50));
	    //printf("i: %d, oct val: %d\n", ip6_byte, oct_val);
	    if (ip6_byte == 0){
	      printf("Error sender: %s\n", inet_ntop(AF_INET6, &ipv6_header->ip6_src.s6_addr, ip6_err_addr_str, 50));
	    }
	  }
	  
	  
	  //printf("Type: %d\n", icmpv6_header->icmp6_type);

	  //printf("\n=========\nsrc octet %d: %d\n", ip6_byte, ipv6_header->ip6_src.s6_addr[ip6_byte]);
	  //printf("desc_count: %d\n", current_node->desc_count);
	  //TODO: go through descendents to check if current value exists
	  //TODO: refactor this, lots of duplicate code
	  //check if this node has any descendents
	  //if not, add new node
	  if (current_node->descendents == NULL){
	      new_desc = (struct addr_byte_node*) malloc(sizeof(struct addr_byte_node));
	      new_desc->bit_val = oct_val;
	      new_desc->parent = current_node;
	      new_desc->descendents = NULL;
	      new_desc->next = NULL;
	      new_desc->prev = NULL;
	      current_node->descendents = new_desc;
              //printf("initial layer node added: %d (%d), parent %d\n", oct_val, current_node->descendents->bit_val, new_desc->parent->bit_val);
	      current_node = new_desc;
	  //check if any descendents match the current byte value
	  } else {
	      //first node matches
	      new_desc = current_node->descendents;
	      if (new_desc->bit_val == oct_val){
	        current_node = new_desc;
		//printf("path found on first instance\n");
	      //no second node present
	      } else if (new_desc->next == NULL){
		new_desc->next = (struct addr_byte_node*) malloc(sizeof(struct addr_byte_node));
		//printf("oct-val: %d, second node val: %d\n", oct_val, new_desc->bit_val);
		new_desc->next->prev = new_desc;
		new_desc = new_desc->next;
                new_desc->bit_val = oct_val;
	        new_desc->parent = current_node;
	        new_desc->descendents = NULL;
	        new_desc->next = NULL;
	        new_desc->prev = current_node;
		current_node->next = new_desc;
	        current_node = new_desc;
	      //first node doesn't match, more than one node present: iterate through linked list values
	      } else {
		while (new_desc->next){
	          new_desc = new_desc->next;
		  //printf("oct-val: %d, cycle node val: %d\n", oct_val, new_desc->bit_val);
		  if (new_desc->bit_val == oct_val){
		    //printf("path found: desc addr oct %d: %d\n", oct_val, new_desc->bit_val);
		    current_node = new_desc;
		    break;
		  }
		  //if no matches, add new node on the end of this linked list (ie. octet layer)
		  if (!new_desc->next){
		    //printf("no path found, adding new node in layer: desc addr oct %d: %d\n", oct_val, new_desc->bit_val);
		    new_desc->next = (struct addr_byte_node*) malloc(sizeof(struct addr_byte_node));
	            new_desc->next->prev = new_desc;
		    new_desc = new_desc->next;
                    new_desc->bit_val = oct_val;
		    new_desc->parent = new_desc->prev->parent;
	   	    new_desc->descendents = NULL;
		    new_desc->next = NULL;
		    new_desc->prev = current_node;
		    current_node = new_desc;
		  }
		}
	      }
	  }

	  //if this is a leaf node, add ICMPv6 response type
	  if (ip6_byte == 7){
	    //TODO: find a neater way of allocating mem for string
            icmpv6_str = (char*) malloc(20);
	    //strcpy(icmpv6_str, "ICMPv6 Placeholder");
	    strcpy(icmpv6_str, icmpv6_msg_str);
	    current_node->icmpv6_msg = icmpv6_str;
	    printf("ICMPv6 msg for node %d: %s\n-----------\n", current_node->bit_val, current_node->icmpv6_msg);
	  }
	}

	//}
}



void print_packet_info(u_char *info, const u_char *packet, struct pcap_pkthdr packet_header) {
  
  struct ether_header *eth_header;
  int ipv6_header_length;
  struct ip6_hdr *ipv6_header;
  struct icmp6_hdr *icmpv6_header;
  eth_header = (struct ether_header *) packet;
  ipv6_header = (struct ip6_hdr*) (packet + sizeof(struct ether_header));
  icmpv6_header = (struct icmp6_hdr*) (packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));

  struct capture_info *i;
  i = (struct capture_info *) info;
  int oct_val = 0;
  struct addr_byte_node* current_node;
  struct addr_byte_node* new_desc;
  
  //printf("Current_node not allocated yet \n");
  current_node = i->addr_tree_root;
  //printf("Current_node allocated \n");
  
  struct pfx *new_pfx;

  char icmpv6_str[50];

  char ipv6_addr_str[100];
  char ipv6_str_slice[15];

  //icmpv6_str = NULL;

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
        
        if (i->current_pfx->pfx_addr == NULL){
	  //
	  //i->current_pfx->pfx_addr = (char*) malloc(PFX_STR_SIZE);
	  //strcpy(i->current_pfx->pfx_addr, ipv6_str_slice);
	} else if (strcmp(i->current_pfx->pfx_addr, ipv6_str_slice) != 0){
	//} else if (i->current_pfx->pfx_addr != *(ipv6_str_slice)){
	  new_pfx = (struct pfx*) malloc(sizeof(struct pfx));
	  i->current_pfx->next = new_pfx;
	  new_pfx->prev = i->current_pfx;
	  i->current_pfx = new_pfx;
	  i->current_pfx->pfx_addr = (char*) malloc(PFX_STR_SIZE);
	  strcpy(i->current_pfx->pfx_addr, ipv6_str_slice);
	  i->current_pfx->info = (struct capture_info*) malloc(sizeof(struct capture_info));
	}	
        //printf("Slice: %s\n", i->current_pfx->pfx_addr);
        //printf("Str slice: %s\n", ipv6_str_slice);

//printf("ICMPv6\n");
	//printf("type: %d, ", icmpv6_header->icmp6_type);
	//Check for Echo Request
	
      
	//trace_addr_path(current_node, ipv6_header, "Echo Reply");
      
        if (icmpv6_header->icmp6_type == 128){
	  //printf("Echo Req\n");
	  i->echo_req_count++;
	  i->current_pfx->info->echo_req_count++;
	  //not a response, this is an outgoing probe
          //i->total_resp_count++;
	
	  
	  
	  //Check for Echo Reply
	} else if (icmpv6_header->icmp6_type == 129){
	  //no print -> segfault
	  //printf("Echo Reply\n");
          //strcpy(icmpv6_str, "Echo Reply");
	  //printf("\n---------------\nAddr: %s\n", ipv6_addr_str);
	  //trace_addr_path(current_node, ipv6_header, icmpv6_str);
	  //printf("main: ip6: %p, icmp6: %p\n", ipv6_header, icmpv6_header);
	  trace_addr_path(current_node, ipv6_header, icmpv6_header, "Echo Reply");
	  //printf("trace complete\n");
	  i->echo_reply_count++; 
	  //printf("i->referenced\n");
	  i->current_pfx->info->echo_reply_count++; 
          i->total_resp_count++;
          i->current_pfx->info->total_resp_count++;
	//Check for Time Exceeded
	} else if (icmpv6_header->icmp6_type == 3){
	  //printf("Time Exceeded\n");
	  trace_addr_path(current_node, ipv6_header, icmpv6_header, "Time Exceeded");
	  i->time_exceeded_count++;
	  i->total_resp_count++;
	//Check for Destination Unreachable
	} else if (icmpv6_header->icmp6_type == 1){
	    //No Route
	    if (icmpv6_header->icmp6_code == 0){
	       trace_addr_path(current_node, ipv6_header, icmpv6_header, "No Route");
	       i->no_route_count++;
	       i->current_pfx->info->no_route_count++;
	    //Address Unreachable
	    } else if (icmpv6_header->icmp6_code == 3){
	       trace_addr_path(current_node, ipv6_header, icmpv6_header, "Address Unreachable");
	       i->address_unreachable_count++;
	       i->current_pfx->info->address_unreachable_count++;
	    //Communication with destination administratively prohibited
            } else if (icmpv6_header->icmp6_code == 1){
	       trace_addr_path(current_node, ipv6_header, icmpv6_header, "Admin Prohibited");
	       i->admin_prohibited_count++;
	       i->current_pfx->info->admin_prohibited_count++;
	    //Port Unreachable
            } else if (icmpv6_header->icmp6_code == 4){
	       trace_addr_path(current_node, ipv6_header, icmpv6_header, "Port Unreachable");
	       i->port_unreachable_count++;
	       i->current_pfx->info->port_unreachable_count++;
	    //Reject Route to Destination
            } else if (icmpv6_header->icmp6_code == 6){
	       trace_addr_path(current_node, ipv6_header, icmpv6_header, "Reject Route");
	       i->reject_route_count++;
	       i->current_pfx->info->reject_route_count++;
	    //Failed Ingress/Egress Policy
            } else if (icmpv6_header->icmp6_code == 5){
	       trace_addr_path(current_node, ipv6_header, icmpv6_header, "Failed Policy");
	       i->failed_policy_count++;
	       i->current_pfx->info->failed_policy_count++;
            } else {
	       printf("Unhandled ICMPv6 unreachable code: %d\n", icmpv6_header->icmp6_code);
	    }
	    i->total_resp_count++;
	    i->current_pfx->info->total_resp_count++;
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
  
  //allocate root node for IPv6 target address octet tree
  struct addr_byte_node* root_node;
  root_node = (struct addr_byte_node*) malloc(sizeof(struct addr_byte_node));
  root_node->parent = NULL;
  root_node->descendents = NULL;
  root_node->desc_count = 0;
  root_node->bit_val = 0;
  root_node->prev = NULL;
  root_node->next = NULL;
  info.addr_tree_root = root_node;

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
  

  /*
  //TODO: make argument handling less fragile
  FILE* fp;
  char* line;
  size_t line_len;
  int read;
  int mask;
  char* octet_a;

  line = NULL;
  line_len = 0;
  read = 0;
  octet_a = (char*) malloc(4);
  //octet_b = (char*) malloc(2);
  
  fp = fopen(argv[2], "r");
  while((read = getline(&line, &line_len, fp)) != -1){
    printf("line: %s", line);
    for(int i; line[i] != ':'; i++){
      octet_a[i] = line[i];
    }

    printf("octet str: %s\n", octet_a); 
    printf("octet cast to dec ints: %ld, %ld\n", strtol(octet_a, NULL, 16) >> 8, strtol(octet_a, NULL, 16) & 255); 
  }

  fclose(fp);

  */

  /*
  struct pfx *cursor;
  cursor = info.current_pfx;

  while(cursor != NULL){
     printf("List addr: %s, total_resp_count: %d\n", cursor->pfx_addr, cursor->info->total_resp_count);
     cursor = cursor->prev;
     free(cursor->next->pfx_addr);
     free(cursor->next->info);
     free(cursor->next);
  }
 */ 
 
  //for (int ip6_byte = 0; ip6_byte < 8; ip6_byte++){
	  //for Echo Reply, dst field is the same as the intended probe target
	  //if (icmpv6_header->icmp6_type == 129){
  	    //oct_val = ipv6_header->ip6_src.s6_addr[ip6_byte];
 
  printf(
	  "Ongoing count:\nEcho Req: %d\nEcho Reply: %d\nTime Exceeded: %d\nNo Route: %d\nAddress Unreachable: %d\nAdmin Prohibited: %d\nPort Unreachable: %d\nReject Route: %d\nSrc Addr Failed Ingress/Egress Policy: %d\nTotal responses received: %d\n\n", 
	  info.echo_req_count, info.echo_reply_count, info.time_exceeded_count, info.no_route_count, 
	  info.address_unreachable_count, info.admin_prohibited_count, info.port_unreachable_count, 
	  info.reject_route_count, info.failed_policy_count, info.total_resp_count
  );


  return 0;
}



