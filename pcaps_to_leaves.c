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
    int duplicate_probe_count;
    struct pfx* current_pfx;
    struct addr_byte_node* send_tree_root;
    struct addr_byte_node* recv_tree_root;
};

struct advert_info {
    //ie. keep reference to point in the addr byte tree where this advert starts
    struct addr_byte_node* tree_node;
    struct advert_info* next;
    struct advert_info* prev;
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
    int duplicate_probe_count;
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
    struct advert_info* adv_info;
    int duplicate_count;
};



//TODO: implement this
//adds advert info as a node in a linked list
//each node contains information about a single advertisement
//TODO: made these work for advertisements which aren't /48
struct advert_info* create_advert_info_node(struct advert_info* prev_adv, struct addr_byte_node* tree_node){
	struct advert_info* new_adv;

	new_adv = (struct advert_info*)malloc(sizeof(struct advert_info));
        new_adv->tree_node = tree_node;
	new_adv->next = NULL;
	new_adv->prev = prev_adv;
	new_adv->total_resp_count = 0;
	new_adv->echo_req_count = 0;
	new_adv->echo_reply_count = 0;
	new_adv->time_exceeded_count = 0;
	new_adv->no_route_count = 0;
	new_adv->address_unreachable_count = 0;
	new_adv->admin_prohibited_count = 0;
	new_adv->port_unreachable_count = 0;
	new_adv->reject_route_count = 0;
	new_adv->failed_policy_count = 0;
	new_adv->duplicate_probe_count = 0;

        return new_adv;
}

//TODO: make these work for adverts which aren't /48s
void print_adv_addr(struct advert_info* adv){
	
	unsigned char ipv6_pfx_bytes[16];
	char ipv6_addr_str[50];
	struct addr_byte_node* node = adv->tree_node;

	for (int i = 5; i >= 0; i--){
	    ipv6_pfx_bytes[i] = node->bit_val;
	    node = node->parent;
	} 

	for (int j = 6; j <= 15; j++){
	     ipv6_pfx_bytes[j] = 0;
	}
	//ipv6_pfx_bytes[15] = 1;

	inet_ntop(AF_INET6, ipv6_pfx_bytes, ipv6_addr_str, 50);
	//printf("Advertised range starting addr: %s\n", ipv6_addr_str);

}

void print_adv_info(struct advert_info* adv){
        
	printf("adv info:\ntotal_resp_count: %d\n\
echo_req_count: %d\n\
echo_reply_count: %d\n\
time_exceeded_count: %d\n\
no_route_count: %d\n\
address_unreachable_count: %d\n\
admin_prohibited_count: %d\n\
port_unreachable_count: %d\n\
reject_route_count: %d\n\
failed_policy_count: %d\n\
duplicate_count: %d\n",
	
	adv->total_resp_count,
	adv->echo_req_count,
	adv->echo_reply_count,
	adv->time_exceeded_count,
	adv->no_route_count,
	adv->address_unreachable_count,
	adv->admin_prohibited_count,
	adv->port_unreachable_count,
	adv->reject_route_count,
	adv->failed_policy_count,
	adv->duplicate_probe_count);
}


//add information about responses within a specific advertisement
//ie. a node at layer 7 of the tree (6th byte, plus root node) will be the start of a /48 advertisement
//TODO: make this work with advertisements that aren't /48
//each advertisement will have a capture_info element in a linked list
//update a capture_info element of the list with response counts etc 
void update_advert_info(struct advert_info* info, struct addr_byte_node* node){
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

	info->duplicate_probe_count += node->duplicate_count;

	//printf("\n=========\nadv updated (%p, msg %s)\n", info, node->icmpv6_msg);
	print_adv_addr(info);
	//print_adv_info(info);

}


//count all ICMPv6 message types stored in leaf nodes
void traverse_leaf_nodes(struct addr_byte_node* node, struct capture_info* info){
    struct addr_byte_node* current_node = NULL;


    //printf("traverse starting...\n");
    //if (strcmp(node->icmpv6_msg, "aaaa") == 0){
    //if (node->icmpv6_msg == NULL){
	    //printf("NULL found!\n");
    //}
    //if no descendents, this is a leaf node
    if (node->descendents == NULL){
        // add stat to info
	//printf("no descendents - starting else if checks\n");
        //printf("\n-------\nleaf: %d\n", node->bit_val);
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
		//printf("Echo Req!\n");
	        info->echo_req_count++;
	}
	//TODO: this assumes all duplicates have the same response type, need to log different responses for same addr
	info->total_resp_count++;
	//printf("resp_count checked\n");
	info->duplicate_probe_count += node->duplicate_count;
	//printf("duplicate_count check\n");
	//printf("\n-------\nleaf: %s, %d\n", node->icmpv6_msg, node->bit_val);
	
	//TODO: make this work for non /48 advertisements
	//TODO: AUG 23 - change leaf nodes to have an advert node field - propagate that down when creating nodes
	//update_advert_info(node->parent->parent->adv_info, node);

	if (node->duplicate_count > 0){
	     //printf("leaf: %s, duplicate count: %d, ", node->icmpv6_msg, node->duplicate_count);
	     unsigned char ipv6_pfx_bytes[16];
	     char ipv6_addr_str[50];
	     for (int i = 15; i >= 0; i--){
	     //for (int i = 7; i >= 0; i--){
	         //printf("pfx_bytes i: %d\n", i);
	         ipv6_pfx_bytes[i] = node->bit_val;
	         //printf("node->bit_val: %d\n", node->bit_val);
		 //printf("node->parent: %p\n", node->parent);
  	         node = node->parent;
	     }

	     //for (int j = 8; j <= 15; j++){
		// ipv6_pfx_bytes[j] = 0;
	     //}
	     //ipv6_pfx_bytes[15] = 1;

             inet_ntop(AF_INET6, ipv6_pfx_bytes, ipv6_addr_str, 50);
	     //printf("Addr: %s\n", ipv6_addr_str);
	     //printf("leaf: %s, %d, duplicate count: %d\n", node->icmpv6_msg, node->bit_val, node->duplicate_count);
	     //sleep(5);
	}
	
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

       //printf("else if block checked - descendents checked\n");
       current_node = node->descendents;
       //printf("non-leaf: %d\n", current_node->bit_val);
       while(current_node){
	       //printf("recursive call\n");
           traverse_leaf_nodes(current_node, info);
	   current_node = current_node->next; 
       }
    }

    //if there is an advertisement starting at this node, all leaf node info has been collected through recursive calls by this point
    //print stats
    /*
	if (node->adv_info != NULL){
	    printf("--------\n");
	    print_adv_addr(node->adv_info);
	    print_adv_info(node->adv_info);
    }
    */
    //printf("end of traverse\n");
}


//add leaf node to existing tree
//TODO: rename to something more descriptive
void add_addr_path(struct addr_byte_node* current_node, struct ip6_hdr* ipv6_header, struct icmp6_hdr* icmpv6_header, char* icmpv6_msg_str){
	
        //struct icmp6_hdr *icmpv6_header;
	unsigned char oct_val;
	struct addr_byte_node* new_desc;
	char* icmpv6_str;
	char* icmpv6_err_target;
	char ip6_addr_str[50];
	char ip6_err_addr_str[50];
	
	icmpv6_header = (struct icmp6_hdr*) (ipv6_header + 1);
	oct_val = 0;
	icmpv6_str = NULL;

	for (int ip6_byte = 0; ip6_byte <= 15; ip6_byte++){
	  //for Echo Reply, src field is (usually) the same as the intended probe target
	  if (icmpv6_header->icmp6_type == 129){
  	    oct_val = ipv6_header->ip6_src.s6_addr[ip6_byte];
	    if (ip6_byte == 0){
	      //printf("Echo reply sender: %s\n", inet_ntop(AF_INET6, &ipv6_header->ip6_src.s6_addr, ip6_addr_str, 50));
	    }
	  //for Echo Request, record target from src addr
	  } else if (icmpv6_header->icmp6_type == 128){
	    oct_val = ipv6_header->ip6_dst.s6_addr[ip6_byte];
	    if (ip6_byte == 0){
	      //printf("Echo req target: %s\n", inet_ntop(AF_INET6, &ipv6_header->ip6_dst.s6_addr, ip6_addr_str, 50));
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
              //printf("Error target: %s\n", inet_ntop(AF_INET6, icmpv6_err_target, ip6_addr_str, 50));
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
	      new_desc->adv_info = NULL;
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
		//printf("oct-val: %d, new node val: %d\n", oct_val, new_desc->bit_val);
		new_desc->next->prev = new_desc;
		new_desc = new_desc->next;
                new_desc->bit_val = oct_val;
	        new_desc->parent = current_node;
	        new_desc->descendents = NULL;
	        new_desc->next = NULL;
		new_desc->adv_info = NULL;
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
		    new_desc->adv_info = NULL;
		    current_node = new_desc;
		  }
		}
	      }
	  }

	  //if this is the 6th byte of the addr, it's the start of an associated /48 advertisement
	  //TODO: make this work for non /48 advertisements
          if ((ip6_byte == 5) && (current_node->adv_info == NULL)){
	      //TODO: make adv_info nodes link together
              current_node->adv_info = create_advert_info_node(NULL, current_node);
	      //printf("adv_info crated at node %d (node: %p, adv_info: %p)\n", current_node->bit_val, current_node, current_node->adv_info);
	      //print_adv_addr(current_node->adv_info);
	  }

	  //if this is a leaf node, check if this value is a duplicate
	  //if first instance of this address (ie. non-duplicate), add ICMPv6 response type
	  if (ip6_byte == 15){
	  //if (ip6_byte == 7){
	    //TODO: find a neater way of allocating mem for string
	    //TODO: refactor to allocate icmpv6 code to leaf addr_byte_node instead of string?
	    //sleep(1);
	    if (current_node->icmpv6_msg == NULL){
                //printf("Null icmpv6 string\n");
		current_node->duplicate_count = 0;
		;
	    } else {
	        //printf("Non-null icmpv6 string, potential duplicate.\n");
                current_node->duplicate_count++;
	    }
            icmpv6_str = (char*) malloc(20);
	    //strcpy(icmpv6_str, "ICMPv6 Placeholder");
	    strcpy(icmpv6_str, icmpv6_msg_str);
	    current_node->icmpv6_msg = icmpv6_str;
	    //printf("icmpv6_str: %s\n", icmpv6_str);
            
            current_node->descendents = NULL;

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
  current_node = i->recv_tree_root;
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
	  add_addr_path(i->send_tree_root, ipv6_header, icmpv6_header, "Echo Request");
	  i->echo_req_count++;
	  i->current_pfx->info->echo_req_count++;
	  //not a response, this is an outgoing probe
	  
	  //Check for Echo Reply
	} else if (icmpv6_header->icmp6_type == 129){
	  //printf("Echo Reply\n");
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
	       //printf("No Route\n");
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
        printf("File %d: %s\n", count, entry->d_name);
	strcpy(abs_path, dirname);
	strcat(abs_path, "/");
	strcat(abs_path, entry->d_name);
	printf("Absolute: %s\n", abs_path);
        handle = pcap_open_offline(abs_path, error_buffer);
	pcap_loop(handle, 0, my_packet_handler, (u_char*)info);
	printf("Loop done.\n");
       	
      } else {
        printf("Skipping file %s\n", entry->d_name);
      }
    } else {
      printf("Skipping file %s\n", entry->d_name);
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
  info.duplicate_probe_count = 0;

  struct pfx* current_pfx;
  
  //allocate root node for IPv6 target address octet tree
  //separate trees for send and receive
  struct addr_byte_node* recv_root_node;
  recv_root_node = (struct addr_byte_node*) malloc(sizeof(struct addr_byte_node));
  recv_root_node->parent = NULL;
  recv_root_node->descendents = NULL;
  recv_root_node->desc_count = 0;
  recv_root_node->bit_val = 0;
  recv_root_node->prev = NULL;
  recv_root_node->next = NULL;
  recv_root_node->duplicate_count = 0;
  info.recv_tree_root = recv_root_node;

  struct addr_byte_node* send_root_node;
  send_root_node = (struct addr_byte_node*) malloc(sizeof(struct addr_byte_node));
  send_root_node->parent = NULL;
  send_root_node->descendents = NULL;
  send_root_node->desc_count = 0;
  send_root_node->bit_val = 0;
  send_root_node->prev = NULL;
  send_root_node->next = NULL;
  send_root_node->duplicate_count = 0;
  info.send_tree_root = send_root_node;


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
	printf("Send dir: %s\n", argv[i]);
        dir_loop(argv[i], &info);
    } else if (strstr(argv[i], "recv") != NULL){
	printf("Recv dir: %s\n", argv[i]);
	dir_loop(argv[i], &info);
    } else {
       printf("Other: %s\n", argv[i]);
       dir_loop(argv[i], &info);
    }
  }
  
  /*
  printf(
	  "Original info count:\nEcho Req: %d\nEcho Reply: %d\nTime Exceeded: %d\nNo Route: %d\nAddress Unreachable: %d\nAdmin Prohibited: %d\nPort Unreachable: %d\nReject Route: %d\nSrc Addr Failed Ingress/Egress Policy: %d\nTotal responses received: %d\n\n", 
	  info.echo_req_count, info.echo_reply_count, info.time_exceeded_count, info.no_route_count, 
	  info.address_unreachable_count, info.admin_prohibited_count, info.port_unreachable_count, 
	  info.reject_route_count, info.failed_policy_count, info.total_resp_count
  );
  */


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
    info_tree->duplicate_probe_count = 0;

    printf("info_tree set up\n");

    if (info.send_tree_root->descendents){
      traverse_leaf_nodes(info.send_tree_root, info_tree);
    }
    printf("send tree complete\n");
    if (info.recv_tree_root->descendents){
        traverse_leaf_nodes(info.recv_tree_root, info_tree);
    }
    printf("recv tree complete\n");


    printf("Tree info count:\nEcho Req: %d\nEcho Reply: %d\nTime Exceeded: %d\nNo Route: %d\nAddress Unreachable: %d\nAdmin Prohibited: %d\nPort Unreachable: %d\nReject Route: %d\nSrc Addr Failed Ingress/Egress Policy: %d\nTotal responses: %d\nDuplicate response count: %d\n\n", 
    info_tree->echo_req_count, info_tree->echo_reply_count, info_tree->time_exceeded_count, info_tree->no_route_count, 
    info_tree->address_unreachable_count, info_tree->admin_prohibited_count, info_tree->port_unreachable_count, 
    info_tree->reject_route_count, info_tree->failed_policy_count, info_tree->total_resp_count, 
    info_tree->duplicate_probe_count);


  return 0;
}



