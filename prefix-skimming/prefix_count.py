import sys

def count_prefixes(bgp_pfx_fname):
    bgp_pfx_file = open(bgp_pfx_fname, "r")
    prefix_counts = {}
    total = 0
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
    print("total records: {num}".format(num=total))


count_prefixes(sys.argv[1])
