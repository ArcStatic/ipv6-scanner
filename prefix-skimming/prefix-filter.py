import sys
import ipaddress

def remove_duplicates(raw_file):
    addrs = raw_file.readlines()
    #convert str to IPv6 object
    for i in range(len(addrs)):
        #strict implicitly set to true, no host bits allowed to be set
        addrs[i] = ipaddress.IPv6Network(addrs[i][:-1])
    uniques = set(addrs)
    if "--filter-only" in sys.argv:
        for x in uniques:
            print(x, end = '')
    return uniques

'''
# returns a dict where keys are the largest advertised address ranges
# overlaps in address ranges occur where a subset of another prefix has been advertised
# values are lists of subdomains which are encompassed by the key (ie. the larger domain)
# an element in the values list which is itself a list incidates a chain of subdomains
# 
# eg: prefixA/32 = [prefixB/40, [prefixC/40, [prefixD/48, prefixE/42]], [prefixF/38, [prefixG/52]]]
# key = prefix A (ie. head of the chain)
# solo IPv6Network item = prefixB (ie. leaf node with no dependents or parent other than head of tree)
# non-leaf node = prefixC, prefixF (ie. have dependents)
# leaf nodes = prefixD, prefixE, prefixG 

#TODO: refactor into generic tree structure
'''
def find_subsets(addr_set):
    subsets = {}
    for x in addr_set:
        for y in addr_set:
            if x.overlaps(y) and x != y:
                #print("overlap between %s and %s" % (x, y))
                #if prefix for y is larger than prefix for x, addr range y is a subset of addr range x
                if x.prefixlen < y.prefixlen:
                    subsets.setdefault(x, [])
                    #if y is already a key, then y has advertised subranges - there is a chain here
                    #(eg. /32 containing /40 containing /48)
                    if y in subsets.keys():
                        #print("\n\n\ny-based chain found:\nx: %s\ny: %s" % (subsets[x], subsets[y]))
                        subsets[x].append([y, subsets[y]])
                        #print("key %s: val %s" % (x, subsets[x]))
                        del subsets[y]
                    else:
                        subsets[x].append(y)
                else:
                    subsets.setdefault(y, [])
                    #same chain check as above
                    if x in subsets.keys():
                        #print("\n\n\nx-based chain found:\nx: %s\ny: %s" % (subsets[x], subsets[y]))
                        subsets[y].append([x, subsets[x]])
                        #print("key %s: val %s" % (y, subsets[y]))
                        del subsets[x]
                    else:
                        subsets[y].append(x)
    print("\n\n\n\n\n")
    return subsets

f = open(sys.argv[1])
uniques = remove_duplicates(f)
f.close()
subsets = find_subsets(uniques)

for k, subset_list in subsets.items():
    print("%s: %s\n" % (k, subset_list))
