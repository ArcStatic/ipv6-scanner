import sys

def count_prefixes(bgp_pfx_fname):
    bgp_pfx_file = open(bgp_pfx_fname, "r")
    prefix_counts = {}
    total = 0
    scannable_total = 0
    total_networks = 0

    for line in bgp_pfx_file:
        mask = line.split("/")[1][:-1]
        #print(mask)
        if mask not in prefix_counts:
            prefix_counts[mask] = 1
        else:
            prefix_counts[mask] += 1
        total += 1
    bgp_pfx_file.close()
    #print(prefix_counts.keys())
    for key, val in sorted(prefix_counts.items()):
        print("mask /{key}: count {val} ({p}%)".format(key = key, val = val, p = (val/total)*100))
        if int(key) >=48 and int(key) <=64:
            scannable_total += int(val)
            total_networks += 2**(64 - int(key)) * int(val)
    print("\ntotal records: {num}".format(num=total))

    print("Total scannable pfxs: {pfx_total} ({p}%)".format(pfx_total=scannable_total, p=(scannable_total/total)*100))
    print("Predicted number of /64s: {tn}".format(tn=total_networks))


count_prefixes(sys.argv[1])
