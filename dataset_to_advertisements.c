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



void process_packets(u_char *info, const u_char *packet, struct pcap_pkthdr packet_header) {
  
  struct ether_header *eth_header;
  struct ip6_hdr *ipv6_header;
  struct icmp6_hdr *icmpv6_header;
  eth_header = (struct ether_header *) packet;
  ipv6_header = (struct ip6_hdr*) (packet + sizeof(struct ether_header));
  icmpv6_header = (struct icmp6_hdr*) (packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));

  unsigned char ipv6_pfx_bytes[16];
  char ipv6_addr_str[50];
  char ip6_addr_str[50];
  char* icmpv6_err_target;
  pcap_dumper_t *pd;
  
  //printf("\n--------\n");

  if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
    printf("IP\n");
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
    printf("ARP\n");
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP) {
    printf("Reverse ARP\n");
  } else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
      //ICMPv6 payload
      if (ipv6_header->ip6_nxt == 58) {


	//printf("type: %d, \n", icmpv6_header->icmp6_type);
	
	//Check for Echo Request
        if (icmpv6_header->icmp6_type == 128){
	  //printf("Echo Request\n");
	  for (int i = 5; i >= 0; i--){
	      ipv6_pfx_bytes[i] = ipv6_header->ip6_dst.s6_addr[i];
	  } 

	  for (int j = 6; j <= 15; j++){
	      ipv6_pfx_bytes[j] = 0;
	  }
          inet_ntop(AF_INET6, ipv6_pfx_bytes, ipv6_addr_str, 50);
          //printf("Advertised range starting addr: %s\n", ipv6_addr_str);


	  //not a response, this is an outgoing probe
	  
	  //Check for Echo Reply
	} else if (icmpv6_header->icmp6_type == 129){
	  //printf("Echo Reply\n");

	  //printf("Echo reply sender: %s\n", inet_ntop(AF_INET6, &ipv6_header->ip6_src.s6_addr, ip6_addr_str, 50));
	  for (int i = 5; i >= 0; i--){
	      ipv6_pfx_bytes[i] = ipv6_header->ip6_src.s6_addr[i];
	  } 

	  for (int j = 6; j <= 15; j++){
	      ipv6_pfx_bytes[j] = 0;
	  }
          inet_ntop(AF_INET6, ipv6_pfx_bytes, ipv6_addr_str, 50);
          //printf("Request sent to advertised range: %s\n", ipv6_addr_str);

        //Check for Time Exceeded
	} else if (icmpv6_header->icmp6_type == 3){
	  //printf("Time Exceeded\n");
          
          icmpv6_err_target = (char*) &(icmpv6_header->icmp6_data8) + 28;
	  
	  for (int i = 5; i >= 0; i--){
	      ipv6_pfx_bytes[i] = icmpv6_err_target[i];
	  } 

	  for (int j = 6; j <= 15; j++){
	      ipv6_pfx_bytes[j] = 0;
	  }
          inet_ntop(AF_INET6, ipv6_pfx_bytes, ipv6_addr_str, 50);
          //printf("Advertised range starting addr: %s\n", ipv6_addr_str);


	//Check for Destination Unreachable
	} else if (icmpv6_header->icmp6_type == 1){
	    //printf("Destination Unreachable\n");
	    //No Route
	    if (icmpv6_header->icmp6_code == 0){
	        //printf("No Route\n");
          icmpv6_err_target = (char*) &(icmpv6_header->icmp6_data8) + 28;
	  
	  for (int i = 5; i >= 0; i--){
	      ipv6_pfx_bytes[i] = icmpv6_err_target[i];
	  } 

	  for (int j = 6; j <= 15; j++){
	      ipv6_pfx_bytes[j] = 0;
	  }
          inet_ntop(AF_INET6, ipv6_pfx_bytes, ipv6_addr_str, 50);
          //printf("Advertised range starting addr: %s\n", ipv6_addr_str);


	    //Address Unreachable
	    } else if (icmpv6_header->icmp6_code == 3){
	       //printf("Address Unreachable\n");
          icmpv6_err_target = (char*) &(icmpv6_header->icmp6_data8) + 28;
	  
	  for (int i = 5; i >= 0; i--){
	      ipv6_pfx_bytes[i] = icmpv6_err_target[i];
	  } 

	  for (int j = 6; j <= 15; j++){
	      ipv6_pfx_bytes[j] = 0;
	  }
          inet_ntop(AF_INET6, ipv6_pfx_bytes, ipv6_addr_str, 50);
          //printf("Advertised range starting addr: %s\n", ipv6_addr_str);


	    //Communication with destination administratively prohibited
            } else if (icmpv6_header->icmp6_code == 1){
	       //printf("Administratively Prohibited\n");
          icmpv6_err_target = (char*) &(icmpv6_header->icmp6_data8) + 28;
	  
	  for (int i = 5; i >= 0; i--){
	      ipv6_pfx_bytes[i] = icmpv6_err_target[i];
	  } 

	  for (int j = 6; j <= 15; j++){
	      ipv6_pfx_bytes[j] = 0;
	  }
          inet_ntop(AF_INET6, ipv6_pfx_bytes, ipv6_addr_str, 50);
          //printf("Advertised range starting addr: %s\n", ipv6_addr_str);


	    //Port Unreachable
            } else if (icmpv6_header->icmp6_code == 4){
	       //printf("Port Unreachable\n");
          icmpv6_err_target = (char*) &(icmpv6_header->icmp6_data8) + 28;
	  
	  for (int i = 5; i >= 0; i--){
	      ipv6_pfx_bytes[i] = icmpv6_err_target[i];
	  } 

	  for (int j = 6; j <= 15; j++){
	      ipv6_pfx_bytes[j] = 0;
	  }
          inet_ntop(AF_INET6, ipv6_pfx_bytes, ipv6_addr_str, 50);
          //printf("Advertised range starting addr: %s\n", ipv6_addr_str);


	    //Reject Route to Destination
            } else if (icmpv6_header->icmp6_code == 6){
	       //printf("Reject Route to Destination\n");
          icmpv6_err_target = (char*) &(icmpv6_header->icmp6_data8) + 28;
	  
	  for (int i = 5; i >= 0; i--){
	      ipv6_pfx_bytes[i] = icmpv6_err_target[i];
	  } 

	  for (int j = 6; j <= 15; j++){
	      ipv6_pfx_bytes[j] = 0;
	  }
          inet_ntop(AF_INET6, ipv6_pfx_bytes, ipv6_addr_str, 50);
          //printf("Advertised range starting addr: %s\n", ipv6_addr_str);


	    //Failed Ingress/Egress Policy
            } else if (icmpv6_header->icmp6_code == 5){
	       //printf("Failed Ingress/Egress policy\n");
          icmpv6_err_target = (char*) &(icmpv6_header->icmp6_data8) + 28;
	  
	  for (int i = 5; i >= 0; i--){
	      ipv6_pfx_bytes[i] = icmpv6_err_target[i];
	  } 

	  for (int j = 6; j <= 15; j++){
	      ipv6_pfx_bytes[j] = 0;
	  }
          inet_ntop(AF_INET6, ipv6_pfx_bytes, ipv6_addr_str, 50);
          //printf("Advertised range starting addr: %s\n", ipv6_addr_str);


            } else {
	       //printf("Unhandled ICMPv6 unreachable code: %d\n", icmpv6_header->icmp6_code);

	    }
	//Neighbour Solicitation - ignore
	} else if (icmpv6_header->icmp6_type == 135){
		;
	//Neighbour Advertisement - ignore
	} else if (icmpv6_header->icmp6_type == 136){
		;
	} else {
	  //printf("type: %d\n", icmpv6_header->icmp6_type);
	}
      }
    //printf("Other, ip6_nxt: %d\n", ipv6_header->ip6_nxt);}
  }
  
  //sleep(0.01);
  //printf("end of loop\n");
  //printf("ipv6_addr_str: %s\n", ipv6_addr_str);


  if (icmpv6_header->icmp6_type == 129){
    //printf("Echo reply write: %s\n", inet_ntop(AF_INET6, &ipv6_header->ip6_src.s6_addr, ip6_addr_str, 50));
  }
  
  pd = pcap_dump_open_append((pcap_t *)info, ipv6_addr_str);
  //pd = pcap_dump_open_append((pcap_t *)info, "write_test.pcap");
  //pd = pcap_dump_open((pcap_t *)info, "write_test.pcap");
  pcap_dump((u_char*)pd, &packet_header, packet);
  //pcap_dump_flush(pd);
  pcap_dump_close(pd);
  //sleep(2);
 
}


void my_packet_handler(u_char *info, const struct pcap_pkthdr *packet_header, const u_char *packet_body){
  process_packets(info, packet_body, *packet_header);
}

int dir_loop(char *dirname){
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
        printf("handle: %p\n", handle);
	pcap_loop(handle, 0, my_packet_handler, (unsigned char*)handle);
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

//usage: source, dest
    dir_loop(argv[1]);

}



