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


//count all ICMPv6 message types stored in leaf nodes
void traverse_leaf_nodes(struct addr_byte_node* node, struct capture_info* info){
    struct addr_byte_node* current_node = NULL;

    //if no descendents, this is a leaf node
    if (node->descendents == NULL){
        // add stat to info
        if (strcmp(node->icmpv6_msg, "Echo Reply") == 0){
	        info->echo_reply_count++;
	} else if (strcmp(node->icmpv6_msg, "Time Exceeded") == 0){
	        info->time_exceeded_count++;
	} else if (strcmp(node->icmpv6_msg, "No Route") == 0){
	        info->no_route_count++;
	} else if (strcmp(node->icmpv6_msg, "Address Unreachable") == 0){
	        info->address_unreachable_count++;
	} else if (strcmp(node->icmpv6_msg, "Admin Prohibited") == 0){
	        info->admin_prohibited_count++;
        } else if (strcmp(node->icmpv6_msg, "Port Unreachable") == 0){
	        info->port_unreachable_count++;
        } else if (strcmp(node->icmpv6_msg, "Reject Route") == 0){
	        info->reject_route_count++;
	} else if (strcmp(node->icmpv6_msg, "Failed Policy") == 0){
	        info->failed_policy_count++;
	} else if (strcmp(node->icmpv6_msg, "Echo Request") == 0){
	        info->echo_req_count++;
	}
	info->total_resp_count++;
	//printf("leaf: %s, %d\n", node->icmpv6_msg, node->bit_val);
	
	/*
	  printf(
	  "Ongoing count:\nEcho Req: %d\nEcho Reply: %d\nTime Exceeded: %d\nNo Route: %d\nAddress Unreachable: %d\nAdmin Prohibited: %d\nPort Unreachable: %d\nReject Route: %d\nSrc Addr Failed Ingress/Egress Policy: %d\nTotal responses: %d\n\n", 
	  info->echo_req_count, info->echo_reply_count, info->time_exceeded_count, info->no_route_count, 
	  info->address_unreachable_count, info->admin_prohibited_count, info->port_unreachable_count, 
	  info->reject_route_count, info->failed_policy_count, info->total_resp_count);
        */

    //if descendents, move down to this level
    //then iterate through linked list to trace paths of each descendent in turn
    } else {
       current_node = node->descendents;
       //printf("non-leaf: %d\n", current_node->bit_val);
       while(current_node){
           traverse_leaf_nodes(current_node, info);
	   current_node = current_node->next; 
       }
    }
}


//add leaf node to existing tree
//TODO: rename to something more descriptive
void add_addr_path(struct addr_byte_node* current_node, struct ip6_hdr* ipv6_header, struct icmp6_hdr* icmpv6_header, char* icmpv6_msg_str){
	
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

	for (int ip6_byte = 0; ip6_byte < 8; ip6_byte++){
	  //for Echo Reply, dst field is the same as the intended probe target
	  if (icmpv6_header->icmp6_type == 129){
  	    oct_val = ipv6_header->ip6_src.s6_addr[ip6_byte];
	    //printf("i: %d, oct val: %d\n", ip6_byte, oct_val);
	    if (ip6_byte == 0){
	      //printf("Reply sender: %s\n", inet_ntop(AF_INET6, &ipv6_header->ip6_src.s6_addr, ip6_addr_str, 50));
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
	      //printf("Error sender: %s\n", inet_ntop(AF_INET6, &ipv6_header->ip6_src.s6_addr, ip6_err_addr_str, 50));
	    }
	  }
	  
	  //TODO: refactor this, lots of duplicate code
	  //check if this node has any descendents
	  //if not, add new node
	  if (current_node->descendents == NULL){
	      new_desc = (struct addr_byte_node*) malloc(sizeof(struct addr_byte_node));
	      new_desc->bit_val = oct_val;
	      //printf("new_desc val: %d\n", new_desc->bit_val);
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
	        //new_desc->prev = current_node;
		//tree traversal error was here!
		//current_node->next = new_desc;
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
	    //TODO: refactor to allocate icmpv6 code to leaf addr_byte_node instead of string?
            icmpv6_str = (char*) malloc(20);
	    //strcpy(icmpv6_str, "ICMPv6 Placeholder");
	    strcpy(icmpv6_str, icmpv6_msg_str);
	    current_node->icmpv6_msg = icmpv6_str;

	    //printf("ICMPv6 msg for node %d: %s\n-----------\n", current_node->bit_val, current_node->icmpv6_msg);
	  }
	}

}



void process_packets(u_char *info, const u_char *packet, struct pcap_pkthdr packet_header) {
  
  struct ether_header *eth_header;
  struct ip6_hdr *ipv6_header;
  struct icmp6_hdr *icmpv6_header;
  eth_header = (struct ether_header *) packet;
  ipv6_header = (struct ip6_hdr*) (packet + sizeof(struct ether_header));
  icmpv6_header = (struct icmp6_hdr*) (packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));

  struct capture_info *i;
  i = (struct capture_info *) info;
  int oct_val = 0;
  struct addr_byte_node* current_node;
  
  //printf("Current_node not allocated yet \n");
  current_node = i->addr_tree_root;
  //printf("Current_node allocated \n");
  
  struct pfx *new_pfx;

  if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
    printf("IP\n");
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
    printf("ARP\n");
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP) {
    printf("Reverse ARP\n");
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
      //ICMPv6 payload
      if (ipv6_header->ip6_nxt == 58) {

        //printf("ICMPv6\n");
	//printf("type: %d, ", icmpv6_header->icmp6_type);
	
	//Check for Echo Request
        if (icmpv6_header->icmp6_type == 128){
	  //printf("Echo Req\n");
	  i->echo_req_count++;
	  i->current_pfx->info->echo_req_count++;
	  //not a response, this is an outgoing probe
	  
	  //Check for Echo Reply
	} else if (icmpv6_header->icmp6_type == 129){
	  add_addr_path(current_node, ipv6_header, icmpv6_header, "Echo Reply");
	  i->echo_reply_count++; 
	  i->current_pfx->info->echo_reply_count++; 
          i->total_resp_count++;
          i->current_pfx->info->total_resp_count++;
	//Check for Time Exceeded
	} else if (icmpv6_header->icmp6_type == 3){
	  //printf("Time Exceeded\n");
	  add_addr_path(current_node, ipv6_header, icmpv6_header, "Time Exceeded");
	  i->time_exceeded_count++;
	  i->total_resp_count++;
	//Check for Destination Unreachable
	} else if (icmpv6_header->icmp6_type == 1){
	    //No Route
	    if (icmpv6_header->icmp6_code == 0){
	       add_addr_path(current_node, ipv6_header, icmpv6_header, "No Route");
	       i->no_route_count++;
	       i->current_pfx->info->no_route_count++;
	    //Address Unreachable
	    } else if (icmpv6_header->icmp6_code == 3){
	       add_addr_path(current_node, ipv6_header, icmpv6_header, "Address Unreachable");
	       i->address_unreachable_count++;
	       i->current_pfx->info->address_unreachable_count++;
	    //Communication with destination administratively prohibited
            } else if (icmpv6_header->icmp6_code == 1){
	       add_addr_path(current_node, ipv6_header, icmpv6_header, "Admin Prohibited");
	       i->admin_prohibited_count++;
	       i->current_pfx->info->admin_prohibited_count++;
	    //Port Unreachable
            } else if (icmpv6_header->icmp6_code == 4){
	       add_addr_path(current_node, ipv6_header, icmpv6_header, "Port Unreachable");
	       i->port_unreachable_count++;
	       i->current_pfx->info->port_unreachable_count++;
	    //Reject Route to Destination
            } else if (icmpv6_header->icmp6_code == 6){
	       add_addr_path(current_node, ipv6_header, icmpv6_header, "Reject Route");
	       i->reject_route_count++;
	       i->current_pfx->info->reject_route_count++;
	    //Failed Ingress/Egress Policy
            } else if (icmpv6_header->icmp6_code == 5){
	       add_addr_path(current_node, ipv6_header, icmpv6_header, "Failed Policy");
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
  process_packets(info, packet_body, *packet_header);
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
  */
  
  printf(
	  "Original info count:\nEcho Req: %d\nEcho Reply: %d\nTime Exceeded: %d\nNo Route: %d\nAddress Unreachable: %d\nAdmin Prohibited: %d\nPort Unreachable: %d\nReject Route: %d\nSrc Addr Failed Ingress/Egress Policy: %d\nTotal responses received: %d\n\n", 
	  info.echo_req_count, info.echo_reply_count, info.time_exceeded_count, info.no_route_count, 
	  info.address_unreachable_count, info.admin_prohibited_count, info.port_unreachable_count, 
	  info.reject_route_count, info.failed_policy_count, info.total_resp_count
  );


    struct capture_info* info_tree;
    info_tree = (struct capture_info*) malloc(sizeof(struct capture_info));

    info_tree->total_resp_count = 0;
    info_tree->echo_req_count = 0;
    info_tree->echo_reply_count = 0;
    info_tree->time_exceeded_count = 0;
    info_tree->no_route_count = 0;
    info_tree->address_unreachable_count = 0;
    info_tree->admin_prohibited_count = 0;
    info_tree->port_unreachable_count = 0;
    info_tree->reject_route_count = 0;
    info_tree->failed_policy_count = 0;

    traverse_leaf_nodes(info.addr_tree_root, info_tree);


    printf("Tree info count:\nEcho Req: %d\nEcho Reply: %d\nTime Exceeded: %d\nNo Route: %d\nAddress Unreachable: %d\nAdmin Prohibited: %d\nPort Unreachable: %d\nReject Route: %d\nSrc Addr Failed Ingress/Egress Policy: %d\nTotal responses: %d\n\n", 
    info_tree->echo_req_count, info_tree->echo_reply_count, info_tree->time_exceeded_count, info_tree->no_route_count, 
    info_tree->address_unreachable_count, info_tree->admin_prohibited_count, info_tree->port_unreachable_count, 
    info_tree->reject_route_count, info_tree->failed_policy_count, info_tree->total_resp_count);


  return 0;
}



