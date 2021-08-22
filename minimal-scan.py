#from scapy.all import sr1,IPv6,ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6DestUnreach, AsyncSniffer, send, IPerror6, raw, Raw, sendp, Ether, L3RawSocket
#from scapy import *

import sys
import socket
import ipaddress
import threading
import time
import datetime
import socket


def iterate_bgp_prefix(prefix):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.getprotobyname('ipv6-icmp'))
    #icmp_msg = raw(ICMPv6EchoRequest())
    icmp_msg = b'\x80\0\0\0\0\0\0\0'
    prefixlen = prefix.prefixlen

    #TODO: check if program which just sends packets in a loop to the same address gets the same performance as this - isolate problem with socket or address incrementation system or OS-dependent, etc
    print("start time: {s_time}".format(s_time=datetime.datetime.now()))
    #for i in range(2**16):
    for i in range(2**(64 - prefixlen)):
        #slowdown: ~14 seconds
        #icmp_msg = raw(ICMPv6EchoRequest())
        prefix_iteration = prefix.network_address + (i << 64) + 1
        #prefix_iteration = str(prefix.network_address + 1)
        #prefix_iteration = prefix.network_address
        #sock.sendto(icmp_msg, (str(prefix), 0, 0, 0))
        #sock.sendto(icmp_msg, (addr, 0, 0, 0))
        sock.sendto(icmp_msg, (str(prefix_iteration), 0, 0, 0))
        #sock.sendto(icmp_msg, (str(prefix_iteration), 0, 0, 0))

    print("end time: {e_time}".format(e_time=datetime.datetime.now()))
    print("%d pkts sent" % (2**(64 - prefixlen)))


#send_thread = threading.Thread(target=iterate_bgp_prefix, args=(ipaddress.IPv6Address(sys.argv[1]),))
#send_thread = threading.Thread(target=iterate_bgp_prefix, args=(sys.argv[1],))
#send_thread = threading.Thread(target=iterate_bgp_prefix, args=(ipaddress.IPv6Network(sys.argv[1]),))
#send_thread.start()
iterate_bgp_prefix(ipaddress.IPv6Network(sys.argv[1]))
#iterate_bgp_prefix(sys.argv[1])
#send_thread = threading.Thread(target=iterate_bgp_prefix, args=(sys.argv[1], 30))
#send_thread.start()

