from scapy.all import sr1,IPv6,ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6DestUnreach, AsyncSniffer, send, IPerror6, raw, Raw, sendp, Ether, L3RawSocket
from scapy.utils import PcapWriter
#from scapy import *

import sys
import socket
import ipaddress
import threading
import time
import datetime
import socket

def iterate_bgp_prefix_non_loop(prefix, pfx_timeout):
    prefixlen = prefix.prefixlen
    #ie. number of possible network prefixes
    recv_thread = threading.Thread(target=recv_thread_bgp_prefix, args=[pfx_timeout, prefix])
    recv_thread.start()
 
    print("start time: {s_time}".format(s_time=datetime.datetime.now()))
    for i in range(2**(64 - prefixlen)):
        #only interested in network half of prefix
        #shift i left 64 bits so only this half of the address is searched
        #use arbitrary value 1 for host identifier half
        prefix_iteration = prefix.network_address + (i << 64) + 1   
        icmp_pkt = IPv6(dst=str(prefix_iteration))/ICMPv6EchoRequest()
        #print("sent bgp pfx iteration: {pfx}".format(pfx=prefix_iteration))
        send(icmp_pkt, inter=0, verbose=False)
    print("end time: {e_time}".format(e_time=datetime.datetime.now()))
    print("%d pkts sent" % (2**(64 - prefixlen)))
    time.sleep(pfx_timeout)
    recv_thread.join()

def iterate_bgp_prefix(fname, pfx_timeout):
    pfx_file = open(fname, "r")
    sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.getprotobyname('ipv6-icmp'))
    #icmp_msg = raw(ICMPv6EchoRequest())
    #icmp_msg = b'\x80\0\0\0\0\0\0\0'
    for pfx in pfx_file:
        print("prefix to scan: {prefix}".format(prefix=pfx))
        prefix = ipaddress.IPv6Network(pfx[:-1])
        prefixlen = prefix.prefixlen
        if prefixlen >= 48:
            #ie. number of possible network prefixes
            recv_thread = threading.Thread(target=recv_thread_bgp_prefix, args=[pfx_timeout, prefix])
            recv_thread.start()
         
            print("start time: {s_time}".format(s_time=datetime.datetime.now()))
            for i in range(2**(64 - prefixlen)):
                #only interested in network half of prefix
                #shift i left 64 bits so only this half of the address is searched
                #use arbitrary value 1 for host identifier half
                prefix_iteration = prefix.network_address + (i << 64) + 1
                #icmp_msg = b'\x80\0\0\0\0\0\0\0'
                icmp_msg = raw(ICMPv6EchoRequest())
                sock.sendto(icmp_msg, (str(prefix_iteration), 0, 0, 0))

            print("end time: {e_time}".format(e_time=datetime.datetime.now()))
            print("%d pkts sent" % (2**(64 - prefixlen)))
            time.sleep(pfx_timeout)
            recv_thread.join()
 
def iterate_bgp_prefix_scapy_sockets(fname, pfx_timeout):
    pfx_file = open(fname, "r")
    for pfx in pfx_file:
        print("prefix to scan: {prefix}".format(prefix=pfx))
        prefix = ipaddress.IPv6Network(pfx[:-1])
        prefixlen = prefix.prefixlen
        if prefixlen >= 48:
            #ie. number of possible network prefixes
            recv_thread = threading.Thread(target=recv_thread_bgp_prefix, args=[pfx_timeout, prefix])
            recv_thread.start()
         
            print("start time: {s_time}".format(s_time=datetime.datetime.now()))
            for i in range(2**(64 - prefixlen)):
                #only interested in network half of prefix
                #shift i left 64 bits so only this half of the address is searched
                #use arbitrary value 1 for host identifier half
                prefix_iteration = prefix.network_address + (i << 64) + 1   
                icmp_pkt = IPv6(dst=str(prefix_iteration))/ICMPv6EchoRequest()
                #print("sent bgp pfx iteration: {pfx}".format(pfx=prefix_iteration))
                send(icmp_pkt, inter=0, verbose=False)
            print("end time: {e_time}".format(e_time=datetime.datetime.now()))
            print("%d pkts sent" % (2**(64 - prefixlen)))
            time.sleep(pfx_timeout)
            recv_thread.join()
               

def process_bgp_responses(x, f):
    if x.haslayer(ICMPv6DestUnreach):
        # No Route: prefix is not active/reachable
        if x[ICMPv6DestUnreach].code == 0:
            pass
        # Address Unreachable: prefix is live and reachable
        elif x[ICMPv6DestUnreach].code == 3:
            pass
    # Echo Reply: found a live network and a valid host identifier
    elif x.haslayer(ICMPv6EchoReply):
        pass
    else:
        print("Other response: " + x)
        

#used for testing on Sky network - live hosts timeout, non-existent hosts send ICMPv6 Address Unreachable
def recv_thread_bgp_prefix(recv_timeout, pfx_addr):
    print("recv_thread msg")
    #Active responses will be ICMPv6 Echo Reply (less likely) or Destination Unreachable (more likely)
    #async_recv = AsyncSniffer(timeout=recv_timeout, store=True, filter="ip6", lfilter=lambda x, f: process_bgp_responses(x, f))
    async_recv = AsyncSniffer(timeout=recv_timeout, store=True, filter="ip6", lfilter=lambda x: (x.haslayer(ICMPv6EchoReply) or x.haslayer(ICMPv6DestUnreach)))
    async_recv.start()
    async_recv.join()
     
    responses = async_recv.results
    #if responses:
    fname = "livepfxs_nwpfx{addr}".format(addr=str(pfx_addr).replace(":","-").replace("/","mask"))
    f = open(fname, "w")
    #TODO: handle zero responses received better here
    #else:
        #print("No responses received for pfx {pfx}".format(pfx=str(pfx_addr)))
    for i in responses:
        if i.haslayer(ICMPv6DestUnreach):
            #ICMP Address Unreachable response - nw prefix is active, host is not
            if i[ICMPv6DestUnreach].code == 3:
                #print("Unreachable host {resp}, src {src}".format(resp=i[IPerror6].dst, src=i[IPerror6].src))
                f.write("Unreachable host {resp},src {src_addr}\n".format(resp=i[IPerror6].dst, src_addr=i[IPerror6].src))
                #print("Unreachable host {resp},src {src_addr}\n".format(resp=i[IPerror6].dst, src_addr=i[IPerror6].src))
            elif i.haslayer(ICMPv6EchoReply):
                f.write("Echo Reply {resp}\n".format(resp=i[ICMPv6EchoReply].dst))
                #print("Echo Reply {resp}\n".format(resp=i[ICMPv6EchoReply].dst))
            else:
                f.write("Other: {resp}".format(resp=i.layers()))
                #print("Other: {resp}".format(resp=i.layers()))
    f.close()




def iterate_interface_identifier(prefix, oui):
    #ie. iterate through the missing 24 bits in IID, starting at 1
    responses = []
    for i in range(2**24):
        #need 0xfffe for actual OUI testing, ignore for initial tests
        host_iteration = prefix.network_address + (0xf << 16) + i
        #host_iteration = prefix + oui + 0xfffe + i
        icmp_pkt = IPv6(dst=str(host_iteration))/ICMPv6EchoRequest()
        res = sr1(icmp_pkt, timeout=2, filter="ip6")
        if res == None:
            print("Timeout, no response received within limit. %s" % icmp_pkt.dst)
        elif ICMPv6DestUnreach in res:
            print("Destination unreachable: code %s" % res.code)
        elif ICMPv6EchoReply in res:
            print("Echo reply: %s" % res.src)
            responses.append(res.src)
        else:
            print("Other: %s" % res.show())
        #'''
    print("\n\n===========\nFinal responses: %d\n%s\n\n" % (len(responses), responses))



#addr = address of source machine (ie. machine running this script)
def iterate_interface_identifier_no_reply(prefix, oui, addr):
    #ie. iterate through the missing 24 bits in IID, starting at 1
    responses = []
    for i in range(2**24):
        #need 0xfffe for actual OUI testing, ignore for initial tests
        host_iteration = prefix.network_address + i       
        #genuine OUI testing
        #host_iteration = prefix + oui + 0xfffe + i
        #ie. rotate through 10 possible addresses
        src_iteration = ipaddress.IPv6Address(addr) + (i % 15)
        icmp_pkt = IPv6(src = str(src_iteration), dst=str(host_iteration))/ICMPv6EchoRequest()
        
        send(icmp_pkt, inter=0, verbose=False)
        time.sleep(1/25)
        #if i % 100000 == 0:
            #print("sent: %s" % host_iteration)
        print("sent: %s on src %s" % (host_iteration, src_iteration))

def print_echo_reply(x):
    if x.haslayer(ICMPv6EchoReply):
        print("\nECHO REPLY: %s\n" % x[IPv6].src)


def recv_echo_reply_async():
    #TODO: set timeout to 259200 for actual tests (ie. number of seconds in a 72 hour scan)
    
    #async_recv = AsyncSniffer(count = 10, timeout=250, store=True, filter="ip6", lfilter=lambda x: x.haslayer(ICMPv6EchoReply))
    #async_recv = AsyncSniffer(count = 1000, timeout=200000, store=False, filter="ip6", lfilter=lambda x: print_echo_reply(x))
    async_recv = AsyncSniffer(count = 1000, timeout=200000, store=False, filter="ip6", lfilter=lambda x: print_echo_reply(x))
    async_recv.start()
    async_recv.join()
    '''
    responses = async_recv.results
    print("\n\n===========\nFinal responses: %d\n%s\n\n" % (len(responses), responses))
    for i in responses:
        print(i[IPv6].src)
    '''


def print_unreachable(x):
    if x.haslayer(ICMPv6DestUnreach):
        print("Destination Unreachable: dst " + x[IPerror6].dst + ", src " + x[IPerror6].src)
        #print(x.layers())
        #x.show()
    elif x.haslayer(ICMPv6EchoReply):
        print("EchoReply: dst " + x[IPerror6].dst + ", src " + x[IPerror6].src)
    elif x.haslayer(ICMPv6EchoRequest):
        pass
    else:
        print("Other: ")
        x.show()

def print_responses(x):
    if x.haslayer(ICMPv6EchoRequest):
        print("Req")
    else:
        print("Response: " + x[IPv6].dst)
        

#used for testing on Sky network - live hosts timeout, non-existent hosts send ICMPv6 Address Unreachable
def recv_thread_rate_limit(count, recv_timeout):
    print("recv_thread msg")
    #Active responses will be ICMPv6 Echo Reply (less likely) or Destination Unreachable (more likely)
    async_recv = AsyncSniffer(timeout=recv_timeout, store=True, filter="ip6", lfilter=lambda x: (x.haslayer(ICMPv6EchoReply) or x.haslayer(ICMPv6DestUnreach)))
    async_recv.start()
    async_recv.join()
     
    responses = async_recv.results
    if responses:
        fname = "recvfrom_nwpfx{addr}_count{count}".format(addr=str(responses[0][IPv6].src).replace(":","-"), count=count)
        f = open(fname, "w")
    #TODO: handle zero responses received better here
    else:
        print("No responses received for rate %d" % count)
    for i in responses:
        if i.haslayer(ICMPv6DestUnreach):
            #ICMP Address Unreachable response - nw prefix is active, host is not
            if i[ICMPv6DestUnreach].code == 3:
                #print("Unreachable host {resp}, src {src}".format(resp=i[IPerror6].dst, src=i[IPerror6].src))
                f.write("Unreachable host {resp},src {src_addr}\n".format(resp=i[IPerror6].dst, src_addr=i[IPerror6].src))
            elif i.haslayer(ICMPv6EchoReply):
                f.write("Echo Reply {resp},src {src_addr}\n".format(resp=i[ICMPv6EchoReply].dst, src_addr=i[IPv6].dst))
    f.close()




#used for testing on Sky network - live hosts timeout, non-existent hosts send ICMPv6 Address Unreachable
def recv_non_unreachable_async(count):
    #TODO: set timeout to 259200 for actual tests (ie. number of seconds in a 72 hour scan)
    
    #async_recv = AsyncSniffer(count = 10, timeout=25, store=True, filter="ip6", lfilter=lambda x: x.haslayer(ICMPv6DestUnreach))
    #async_recv = AsyncSniffer(count = 1000000, timeout=20, store=True, filter="ip6", lfilter=lambda x: print_unreachable(x))
    #Active responses will be ICMPv6 Echo Reply (less likely) or Destination Unreachable (more likely)
    async_recv = AsyncSniffer(timeout=10, store=True, filter="ip6", lfilter=lambda x: (x.haslayer(ICMPv6EchoReply) or x.haslayer(ICMPv6DestUnreach)))
    #async_recv = AsyncSniffer(count = 1000000, timeout=2500, store=False, filter="ip6", lfilter=lambda x: print_responses(x))
    #async_recv = AsyncSniffer(count = 100, timeout=60, store=True, filter="ip6", lfilter=lambda x: not x.haslayer(ICMPv6EchoRequest))
    async_recv.start()
    async_recv.join()
     
    responses = async_recv.results
    print("\n\n===========\nFinal responses: %d\n%s\n\n" % (len(responses), responses))
    if responses:
        fname = "recvfrom_nwpfx{addr}_count{count}".format(addr=str(responses[0][IPv6].src).replace(":","-"), count=count)
        f = open(fname, "w")
    #TODO: handle zero responses received better here
    else:
        print("No responses received")
        recv_non_unreachable_async(count+1)
    for i in responses:
        if i.haslayer(ICMPv6DestUnreach):
            #ICMP Address Unreachable response - nw prefix is active, host is not
            if i[ICMPv6DestUnreach].code == 3:
                #print("Unreachable host {resp}, src {src}".format(resp=i[IPerror6].dst, src=i[IPerror6].src))
                f.write("Unreachable host {resp},src {src_addr}\n".format(resp=i[IPerror6].dst, src_addr=i[IPerror6].src))
            elif i.haslayer(ICMPv6EchoReply):
                f.write("Echo Reply {resp},src {src_addr}\n".format(resp=i[ICMPv6EchoReply].dst, src_addr=i[IPv6].dst))
    f.close()
    recv_non_unreachable_async(count+1)

#run_time: number of seconds to run each test for
#current_pkt_rate: number of pkts to send per second
#max_pkt_rate: rate of pkts/s to terminate tests on (likely 100pkts/s)
#              eg. if 100 pkts/s sent without any loss, no further tests needed - rate already exceeds 64pkt/s aim
#addr: recipient address used for testing
#src_addr: address of host used for sending (ie. this machine)
def rate_limit_send(run_time, current_pkt_rate, max_pkt_rate, addr, src_addr, timeout):
    #send X packets per second to an address over a fixed time interval
    #wait 1 hour and repeat with X+1 packets per second
    #ie. send X pkts per second for 180 seconds
    if current_pkt_rate == max_pkt_rate:
        return 0
    else:
        print("\n\n===========\nCurrent pkt rate: %d" % current_pkt_rate)

    #store the src-dst pairs for sent pkts
    send_recv_pairs = []

    recv_thread = threading.Thread(target=recv_thread_rate_limit, args=[current_pkt_rate, timeout])
    recv_thread.start()
    print("recv thread started")

    #for sec in range(run_time):
    #run 1 second bursts for now, change to multi-second runs later
    for sec in range(1):
    #TODO: see if bursty traffic is less successful than more evenly spaced traffic
    #ie. does sending all X pkts as quickly as possible in one second get rate-limited more often than packets
    #sent at 1/X intervals?
    #ie. do endpoints have >1s timeout gaps or is the granularity in seconds?
    #for i in range(run_time * current_pkt_rate):
        for pkt in range(current_pkt_rate):
            host_iteration = ipaddress.IPv6Address(int(addr) + pkt + (sec * current_pkt_rate))
            print(host_iteration)
            
            #genuine OUI testing
            #host_iteration = prefix + oui + 0xfffe + i
            #ie. rotate through 16 possible addresses
            #src_iteration = ipaddress.IPv6Address(src_addr) + (pkt % 15)
            src_iteration = ipaddress.IPv6Address(src_addr)
            icmp_pkt = IPv6(src=str(src_iteration), dst=str(host_iteration))/ICMPv6EchoRequest()

            #res = sr1(icmp_pkt, timeout=5)
            #res = sr1(icmp_pkt, timeout=2, filter="ip6")
            send(icmp_pkt, inter=0, verbose=False)
            send_recv_pairs.append((str(src_iteration), str(host_iteration)))
            #time.sleep(1/64) sends around 43 packets per second
            #time.sleep(1/100) sends around 55.5 packets per second
            #1/150 sends around ? packets per second
            #1/200 sends around 88.7 packets per second
            #no sleep call sends around 181 packets per second
            #if i % 100000 == 0:
                #print("sent: %s" % host_iteration)
            #print("%d-%d sent: %s on src %s" % (sec, pkt, host_iteration, src_iteration))
            #icmp_pkt.show()
        #sleep 1s before sending next X packets
        #time.sleep(timeout)
    #wait 10 sec before next rate limit test (allow rate-limit blocks to expire)
    #TODO: test with 15 min gaps, see if this improves success rates
    #print(send_recv_pairs)
    time.sleep(timeout)
    fname = "sendto_nwpfx{addr}_pktrate{pkt_rate}_runtime{run_time}_max{max_pkt_rate}".format(addr=str(host_iteration).replace(":","-"), pkt_rate=current_pkt_rate, run_time=run_time, max_pkt_rate=max_pkt_rate)
    f = open(fname, "w")
    for pair in send_recv_pairs:
        #note src address as well to take account of src address rotations
        #dst addrs increment by 1 each time to track specific responses
        f.write("src {src},dst {dst}\n".format(dst=pair[0], src=pair[1]))
    f.close()
    recv_thread.join()
    rate_limit_send(run_time, current_pkt_rate+1, max_pkt_rate, addr, src_addr, timeout)



#convert OUI to correct IPv6 address format (ie. flip bit 7 to 1)
def convert_oui(oui):
    flipped_oui = int(oui, 16) ^ 0b000000100000000000000000
    print("{0} -> {1}".format(oui, hex(flipped_oui)))
    return flipped_oui


#test_pfx = ipaddress.IPv6Network("2804:4c14:ab00::/48")
#test_pfx = ipaddress.IPv6Network(sys.argv[1])
#print("test_pfx: {pfx}".format(pfx=test_pfx))
#recv_thread = threading.Thread(target=recv_non_unreachable_async, args=[1])
#send_thread = threading.Thread(target=iterate_interface_identifier_no_reply, args=(None, ""))
#send_thread = threading.Thread(target=rate_limit_send, args=(5, 1, 60, ipaddress.IPv6Address(sys.argv[1]), sys.argv[2], 10))
#send_thread = threading.Thread(target=iterate_bgp_prefix, args=(test_pfx, 60))

send_thread = threading.Thread(target=iterate_bgp_prefix, args=(sys.argv[1], 30))
#send_thread = threading.Thread(target=iterate_bgp_prefix_scapy_sockets, args=(sys.argv[1], 30))
#recv_thread.start()
send_thread.start()

