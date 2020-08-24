import sys
import ipaddress
import copy

def remove_duplicates(raw_file):
    addrs = raw_file.readlines()
    #convert str to IPv6 object
    for i in range(len(addrs)):
        #strict implicitly set to true, no host bits allowed to be set
        addrs[i] = ipaddress.IPv6Network(addrs[i][:-1])
    uniques = set(addrs)
    if "--prefix-count" in sys.argv:
        totals = {}
        for x in uniques:
            #print(x, end = '')
            totals.setdefault(x.prefixlen, 0)
            totals[x.prefixlen] += 1
        for k, v in sorted(list(totals.items())):
            print("prefix: %d, %d instances" % (k,v));
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
    return subsets


'''
# Create a set of tree structures showing chains of prefixes and subprefixes
# TODO: handle cases where there might be more than one parent node
# TODO: handle case where an advertised prefix is the child of a non-root node
# TODO: eliminate cases where a prefix could be added twice (eg. make sure /48 is only added as child of /40 and not of /32 as well)
# HINT: add all new nodes into root_nodes - many will just be left as single items, chains can be filtered separately by checking for non-empty child lists for each key-value pair
'''
def build_trees(addr_set):
    root_nodes = {}
    for x in addr_set:
        #add first item to dictionary if empty
        if not root_nodes:
            root_nodes.setdefault(x, prefix_node(x,None))
        else:
            for y in list(root_nodes):
                #if there is an overlap between a prefix and an existing root node, this prefix item is part of a chain of subdomains
                if x.overlaps(y):
                    #smaller prefix number -> shorter mask - y is the subdomain in this case
                    #x becomes a new root node
                    if x.prefixlen < y.prefixlen:
                        root_nodes.setdefault(x, prefix_node(x, None))
                        root_nodes[x].add_child(copy.deepcopy(root_nodes[y]))
                        root_nodes[x].children[-1].set_parent(root_nodes[x])
                        #print("key %s: val %s" % (x, subsets[x]))
                        del root_nodes[y]
                        break
                    #otherwise, x is the subdomain and can be added as a child of existing root_node or of one of its descendants
                    else:
                        new_node = prefix_node(x, None)
                        update_path(new_node, root_nodes[y])
                        #new_node = prefix_node(x, root_nodes[y])
                        #root_nodes[y].children.append(new_node)

                #if there is no overlap, this prefix is not yet part of a chain and should be added as the root of a new tree
                else:
                    root_nodes.setdefault(x, prefix_node(x, None))
    return root_nodes


def update_path(new_node, existing_node):
    for child in existing_node.children:
        if new_node.addr.overlaps(child.addr) and (new_node.addr.prefixlen > child.addr.prefixlen):
            update_path(new_node, child)
    #base case
    new_node.parent = existing_node
    existing_node.children.append(new_node)
    #determine if new prefix is a parent node for child prefixes of existing node
    #ie. should child array elements be transferred?
    for child in list(existing_node.children):
        if new_node.addr.overlaps(child.addr) and (new_node.addr.prefixlen < child.addr.prefixlen):
            new_node.children.append(child)
            existing_node.children.remove(child)

def print_chain(root_node):
    if root_node.parent == None:
        print("=======\nroot: %s" % root_node.addr)
    for i in root_node.children:
        print("%s, child of %s:" % (i.addr, root_node.addr))
        print_chain(i)

class prefix_node:
    def __init__(self, addr, parent):
        self.parent = parent
        self.addr = addr
        self.children = []

    def set_parent(self, new_parent):
        self.parent = new_parent

    def add_child(self, child):
        self.children.append(child)

f = open(sys.argv[1])
uniques = remove_duplicates(f)
f.close()
#subsets = find_subsets(uniques)
subsets = build_trees(uniques)

if "--print-outputs" in sys.argv:
    #for k, subset_list in subsets.items():
        #print("%s: %s\n" % (k, subset_list))
    for k, subset_list in subsets.items():
        if subset_list.children != []:
            print_chain(subset_list)

