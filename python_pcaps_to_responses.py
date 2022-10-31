import sys
from scapy.all import *


def read_data(pcap_file, overall_stats, duplicate_tracker):
    for packet in PcapReader(pcap_file):
        if packet[IPv6].nh == 58:
            if packet[IPv6].type == 128:
                overall_stats["Echo request"] += 1
                #print("Echo request, src: ", packet[IPv6].src, "dst: ", packet[IPv6].dst)
                #duplicate_tracker[packet[IPv6].src] += 1
                pass
            elif packet[IPv6].type == 129:
                #print("Echo reply, src: ", packet[IPv6].src)
                overall_stats["Echo reply"] += 1
                #duplicate_tracker[packet[IPv6].src] += 1
            elif packet[IPv6].type == 1:
                #print("Destination unreachable, src: ", packet[IPv6].src)
                if packet[IPv6].code == 0:
                    overall_stats["No route"] += 1
                    #print("No route.")
                elif packet[IPv6].code == 1:
                    overall_stats["Admin prohibited"] += 1
                    #print("Admin prohibited.")
                    #print("Intended target: ", (packet[ICMPv6DestUnreach].payload).dst)
                elif packet[IPv6].code == 2:
                    overall_stats["Beyond scope"] += 1
                    #print("Beyond scope of source address.")
                elif packet[IPv6].code == 3:
                    overall_stats["Address unreachable"] += 1
                    #print("Address unreachable.")
                elif packet[IPv6].code == 4:
                    overall_stats["Port unreachable"] += 1
                    #print("Port unreachable.")
                elif packet[IPv6].code == 5:
                    overall_stats["Failed ingress/egress policy"] += 1
                    #print("Source address failed ingress/egress policy.")
                elif packet[IPv6].code == 6:
                    overall_stats["Reject route"] += 1
                    #print("Reject route to destination.")
                elif packet[IPv6].code == 7:
                    overall_stats["Error in source routing header"] += 1
                    #print("Error in source routing header.")

            elif packet[IPv6].type == 3:
                overall_stats["Time exceeded"] += 1
                #print("Time exceeded, src: ", packet[IPv6].src)




stats = {}
duplicate_tracking = {}


stats.setdefault("Echo request", 0)
stats.setdefault("Echo reply", 0)
stats.setdefault("No route", 0)
stats.setdefault("Admin prohibited", 0)
stats.setdefault("Beyond scope", 0)
stats.setdefault("Address unreachable", 0)
stats.setdefault("Port unreachable", 0)
stats.setdefault("Failed ingress/egress policy", 0)
stats.setdefault("Reject route", 0)
stats.setdefault("Error in source routing header", 0)
stats.setdefault("Time exceeded", 0)

read_data(sys.argv[1], stats, duplicate_tracking)


print("\n=======")
adv_str = (sys.argv[1].split('/'))[2]
print("Advert: {adv}".format(adv=adv_str))
for k,v in stats.items():
    print("{msg_type}: {count}".format(msg_type=k, count=v))




