from scapy.all import sr1,IPv6,ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6DestUnreach, AsyncSniffer, send, IPerror6
#from scapy import *

import sys
import socket
import ipaddress
import threading
import time

def iterate_bgp_prefix(prefix):
    prefixlen = prefix.prefixlen
    #ie. number of possible network prefixes
    for i in range(2**(64 - prefixlen)):
        #only interested in network half of prefix
        #shift i left 64 bits so only this half of the address is searched
        #use arbitrary value 1 for host identifier half
        prefix_iteration = prefix.network_address + (i << 64) + 1   
        icmp_pkt = IPv6(dst=str(prefix_iteration))/ICMPv6EchoRequest()
        #send - send packets at layer 3
        #sr - send packets and match reply
        #sr1 - send packets, but only match first reply
        res = sr1(icmp_pkt, timeout=15)
        #invalid/unadvertised prefix or host identifier, DROP policy on final hop
        if res == None:
            print("Timeout, no response received.")
        #note: .show() displays None, but prints packet details before print line
        elif ICMPv6EchoReply in res:
            print("Echo reply - host found:\n%s" % res.show())
        #code 3 = Destination Unreachable: Address Unreachable
        #ie. live network prefix found, no matching host ID
        elif ICMPv6DestUnreach in res:
            if res[ICMPv6DestUnreach].code == 3:
                print("Destination unreachable:\n%s, %s" % (res.show(), "Address Unreachable"))
            #code 0 = Destination Unreachable: No Route
            #invalid/unadvertised prefix, REJECT policy on final hop
            elif res[ICMPv6DestUnreach].code == 0:
                print("Destination unreachable:\n%s, %s" % (res.show(), "No route"))
        else:
            print("Other: %s" % res.show())


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
def recv_non_unreachable_async(count):
    #TODO: set timeout to 259200 for actual tests (ie. number of seconds in a 72 hour scan)
    
    #async_recv = AsyncSniffer(count = 10, timeout=25, store=True, filter="ip6", lfilter=lambda x: x.haslayer(ICMPv6DestUnreach))
    #async_recv = AsyncSniffer(count = 1000000, timeout=20, store=True, filter="ip6", lfilter=lambda x: print_unreachable(x))
    #Active responses will be ICMPv6 Echo Reply (less likely) or Destination Unreachable (more likely)
    async_recv = AsyncSniffer(timeout=15, store=True, filter="ip6", lfilter=lambda x: (x.haslayer(ICMPv6EchoReply) or x.haslayer(ICMPv6DestUnreach)))
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
        recv_non_unreachable_async()
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
def rate_limit_send(run_time, current_pkt_rate, max_pkt_rate, addr, src_addr):
    #send X packets per second to an address over a fixed time interval
    #wait 1 hour and repeat with X+1 packets per second
    #ie. send X pkts per second for 180 seconds
    if current_pkt_rate == max_pkt_rate:
        return 0
    else:
        print("\n\n===========\nCurrent pkt rate: %d" % current_pkt_rate)

    #store the src-dst pairs for sent pkts
    send_recv_pairs = []

    for sec in range(run_time):
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
        time.sleep(1)
    #wait 1 min before next rate limit test (allow rate-limit blocks to expire)
    #TODO: test with 15 min gaps, see if this improves success rates
    #print(send_recv_pairs)
    time.sleep(10)
    fname = "sendto_nwpfx{addr}_pktrate{pkt_rate}_runtime{run_time}_max{max_pkt_rate}".format(addr=str(host_iteration).replace(":","-"), pkt_rate=current_pkt_rate, run_time=run_time, max_pkt_rate=max_pkt_rate)
    f = open(fname, "w")
    for pair in send_recv_pairs:
        #note src address as well to take account of src address rotations
        #dst addrs increment by 1 each time to track specific responses
        f.write("src {src},dst {dst}\n".format(dst=pair[0], src=pair[1]))
    f.close()
    rate_limit_send(run_time, current_pkt_rate+1, max_pkt_rate, addr, src_addr)



#convert OUI to correct IPv6 address format (ie. flip bit 7 to 1)
def convert_oui(oui):
    flipped_oui = int(oui, 16) ^ 0b000000100000000000000000
    print("{0} -> {1}".format(oui, hex(flipped_oui)))
    return flipped_oui



recv_thread = threading.Thread(target=recv_non_unreachable_async, args=[1])
#send_thread = threading.Thread(target=iterate_interface_identifier_no_reply, args=(None, ""))
send_thread = threading.Thread(target=rate_limit_send, args=(5, 1, 60, ipaddress.IPv6Address(sys.argv[1]), sys.argv[2]))
recv_thread.start()
send_thread.start()
