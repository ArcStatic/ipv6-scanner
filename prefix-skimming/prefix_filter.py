import sys
import ipaddress

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
# Create a dictionary of tree structures showing chains of prefixes and subprefixes
# TODO: handle cases where there might be more than one parent node
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
                        root_nodes[x].add_child(root_nodes[y])
                        root_nodes[x].children[-1].set_parent(root_nodes[x])
                        #print("key %s: val %s" % (x, subsets[x]))
                        del root_nodes[y]
                        break
                    #otherwise, x is the subdomain and can be added as a child of existing root_node or of one of its descendants
                    else:
                        new_node = prefix_node(x, None)
                        update_path(new_node, root_nodes[y])

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

def process_data(filename):
    f = open(filename)
    uniques = remove_duplicates(f)
    f.close()
    subsets = build_trees(uniques)

    if "--print-outputs" in sys.argv:
        for k, subset_list in subsets.items():
            if subset_list.children != []:
                print_chain(subset_list)
    return subsets

