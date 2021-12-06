import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sr1,IPv6,ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6DestUnreach, AsyncSniffer, send, IPerror6, raw, Raw, sendp, Ether, L3RawSocket
from scapy.utils import PcapWriter
#from scapy import *

import sys
import socket
import ipaddress
import time
import datetime
import socket
import random

def iterate_bgp_prefix(fname):
    pfx_file = open(fname, "r")
    sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.getprotobyname('ipv6-icmp'))
    scanned_count = 0
    total_ads = 0
    eligible_ads = 0
    pkts_sent = 0
    totals = {}
    #rand_iid = random.randint(1, 2**64)
    #print("Randomised 64-bit IID: {r}".format(r=rand_iid))

    for pfx in pfx_file:
        if total_ads % 100 == 0:
            print("\nread %d lines so far" % total_ads)
            print("Scanned %d out of %d eligible advertisements." % (scanned_count, eligible_ads))
            print("Packets sent: %d\n" % pkts_sent)
 
        #print("prefix to scan: {prefix}".format(prefix=pfx[:-1]))
        #ie. 10% chance of scanning a given advertisement
        prefix = ipaddress.IPv6Network(pfx[:-1])
        prefixlen = prefix.prefixlen
        if prefixlen >= 48 and prefixlen <= 64:
            eligible_ads += 1
            #ie. 20% of a prefix being scanned
            if random.randint(1,5) == 4:
                #ie. number of possible network prefixes
                #print("start time: {s_time}".format(s_time=datetime.datetime.now()))
                for i in range(2**(64 - prefixlen)):
                    #ie. 10% chance of scanning a given /64 in this network
                    if random.randint(1, 10) == 4:
                        #only interested in network half of prefix
                        #shift i left 64 bits so only this half of the address is searched
                        #use arbitrary value 1 for host identifier half

                        #IID == randomised 64-bit int chosen earlier - consistent for all probes
                        #prefix_iteration = prefix.network_address + (i << 64) + rand_iid
                        #IID == 1
                        prefix_iteration = prefix.network_address + (i << 64) + 1
                        icmp_msg = raw(ICMPv6EchoRequest())
                        sock.sendto(icmp_msg, (str(prefix_iteration), 0, 0, 0))
                        pkts_sent += 1

                #print("end time: {e_time}".format(e_time=datetime.datetime.now()))
                #print("%d pkts sent" % (2**(64 - prefixlen)))
                print("prefix to scan: {prefix}".format(prefix=pfx[:-1]))
                scanned_count += 1
                #pkts_sent += (2**(64 - prefixlen))
                totals.setdefault(prefixlen, 0)
                totals[prefixlen] += 1
            #else:
                #print("prefix NOT SELECTED: {prefix}".format(prefix=pfx[:-1]))
        total_ads += 1
        #if total_ads == 8600:
            #break
        #if total_ads == 1000:
            #break
    print("Scanned %d out of %d eligible advertisements." % (scanned_count, eligible_ads))
    print("Packets sent: %d" % pkts_sent)
    for k, v in sorted(list(totals.items())):
        print("prefix: %d, %d instances" % (k,v));




iterate_bgp_prefix(sys.argv[1])

