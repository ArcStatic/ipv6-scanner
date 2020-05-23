import sys
import ipaddress

def remove_duplicates(raw_file):
    addrs = raw_file.readlines()
    #convert str to IPv6 object
    for i in range(len(addrs)):
        addrs[i] = ipaddress.IPv6Network(addrs[i][:-1])
    uniques = set(addrs)
    if "--filter-only" in sys.argv:
        for x in uniques:
            print(x, end = '')
    return uniques


def find_overlaps(addr_set):
    for x in addr_set:
        for y in addr_set:
            if x.overlaps(y) and x != y:
                print("overlap between %s and %s" % (x, y))

f = open(sys.argv[1])
uniques = remove_duplicates(f)
f.close()
find_overlaps(uniques)
