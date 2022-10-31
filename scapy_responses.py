from scapy.all import rdpcap, ICMPv6DestUnreach, ICMPv6EchoReply, IPv6, IPerror6, ICMPv6TimeExceeded, ICMPv6ND_NS, ICMPv6EchoRequest
import sys


def recv_processing(pcap_file):
    packets = rdpcap(pcap_file)

    addr_unreach = 0
    no_route = 0
    echo_reply = 0
    time_exceeded = 0
    nd_ns = 0
    other = 0

    for packet in packets:
        if packet.haslayer(ICMPv6DestUnreach):
            if packet[ICMPv6DestUnreach].code == 0:
                #print("No Route, {addr}".format(addr=packet[IPerror6].dst))
                #print("No Route: {layers}".format(layers=packet.layers))
                #packet.show()
                no_route += 1
            if packet[ICMPv6DestUnreach].code == 3:
                #print("Address Unreachable, {addr}".format(addr=packet[IPerror6].dst))
                #print("Addr Unreach: {layers}".format(layers=packet.layers))
                #packet.show()
                addr_unreach += 1
        elif packet.haslayer(ICMPv6EchoReply):
            #print("Echo Reply, {addr}".format(addr=packet[IPv6].src))
            #print("Echo Reply: {layers}".format(layers=packet.layers))
            #packet.show()
            echo_reply += 1
        elif packet.haslayer(ICMPv6TimeExceeded):
            time_exceeded += 1
        elif packet.haslayer(ICMPv6ND_NS):
            nd_ns += 1
        else:
            print("Other response: {layers}".format(layers=packet.layers))
            #packet.show()
            other += 1
    
    print("==========\nProcessing for recv file (fname):\n".format(fname=sys.argv[1]))
    print("Echo Reply: {e}\nAddress Unreachable: {a}\nNo Route: {n}\nTime Exceeded: {h}\nOther: {o}\n".format(e=echo_reply, a=addr_unreach, n=no_route, o=other, h=time_exceeded))
    print("Responsive: {res}\nNot responsive: {n}\nUnknown: {u}\nTotal: {t}".format(res=(echo_reply+addr_unreach), n=no_route, u=(other+time_exceeded), t=(echo_reply+addr_unreach+no_route+other+time_exceeded - nd_ns)))
    print("nd_ns: %d" % nd_ns)



def send_processing(pcap_file):
    packets = rdpcap(pcap_file)

    echo_req = 0
    other = 0

    for packet in packets:
        if packet.haslayer(ICMPv6EchoRequest):
            if packet[ICMPv6DestUnreach].code == 0:
                #print("Echo Request, {addr}".format(addr=packet[ICMPv6EchoRequest].dst))
                #print("Echo Request: {layers}".format(layers=packet.layers))
                #packet.show()
                echo_req += 1
        else:
            print("Other response: {layers}".format(layers=packet.layers))
            #packet.show()
            other += 1
    
    print("==========\nProcessing for send file (fname):\n".format(fname=sys.argv[1]))
    print("Echo Request: {e}\nOther: {o}\nTotal: {t}\n".format(e=echo_req, o=other,t=(echo_req+other)))


if "recv" in sys.argv[1]:
    print("Recv processing, {fname}".format(fname=sys.argv[1]))
    recv_processing(sys.argv[1])
elif "send" in sys.argv[1]:
    print("Send processing, {fname}".format(fname=sys.argv[1]))
    send_processing(sys.argv[1])
