import matplotlib.pyplot as plt
import matplotlib.transforms as mtransforms
import matplotlib.patches as patch
import matplotlib.lines as lines
import sys
import ipaddress

from prefix_filter import process_data

def add_child_nodes(node, x_list, y_list, baseline, ax):
    for i in node.children:
        if int(i.addr.network_address) - baseline < 0:
            print("%s (%d)" % (node.addr, int(node.addr.network_address)))
            print("%s (%d)" % (i.addr, int(i.addr.network_address)))
        #print("baseline: %d" % baseline)
        #print("%d - baseline = %d\n\n" % (int(i.addr.network_address), int(i.addr.network_address) - baseline))
            print("%d - baseline = %d\n\n" % (int(i.addr.network_address), int(i.addr.network_address) - baseline))
        rect = patch.Rectangle((i.addr.prefixlen, int(i.addr.network_address) - baseline), (128 - i.addr.prefixlen), (int(i.addr[-1]) - int(i.addr.network_address)), alpha=0.2, color="red")
        ax.add_patch(rect)
        x_list.append(i.addr.prefixlen)
        y_list.append(int(node.addr.network_address) - baseline)
        add_child_nodes(i, x_list, y_list, baseline, ax)

def collect_indirect_superprefixes(offset_items, node):
    for i in node.children:
        if i.children and (i.addr.prefixlen in offset_items.keys()):
            offset_items[i.addr.prefixlen].append(i)
        elif i.children and (i.addr.prefixlen not in offset_items.keys()):
            offset_items[v.addr.prefixlen] = [v]
        collect_indirect_superprefixes(offset_items, i)

#===================
#plot points w/ data
root_nodes = process_data(sys.argv[1])
offset_items = {}

#collect items by prefix length, so that their immediate subdomains can be plotted relative to the start of the parent advertisement's address space
#potentially identify allocation patterns
for k, v in root_nodes.items():
    if v.children:
        #if an entry for this prefix already exists, add to it
        if v.addr.prefixlen in offset_items.keys():
            offset_items[v.addr.prefixlen].append(v)
        else:
            offset_items[v.addr.prefixlen] = [v]
        #go through and check if any child nodes also have children
        collect_indirect_superprefixes(offset_items, v)

for k, v in offset_items.items():
    fig = plt.figure()
    ax = fig.add_subplot(111)
    ipv6_ints = []
    ipv6_masks = []
    print("\n======\n%d" % k)
    #create a rectangle which encompasses all possible addresses which could be allocated within a given advertisement
    #v.addr[-1] is the last valid address in a range (ie. all free bits set to 1/free hex values set to f)
    #y-axis is the offset from the lowest possible address value in this address range (ie. the range permitted by the root/largest advertisement given)
    #ie. the canvas is effectively a rectangle showing the space of the largest advertisement in the chain
    #plot only the first value for context - the other items in the array will only have their subprefixes plotted
    rect = patch.Rectangle((v[0].addr.prefixlen, 0), (128 - v[0].addr.prefixlen), (int(v[0].addr[-1]) - int(v[0].addr.network_address)), alpha=0.2, color="red")
    ax.add_patch(rect)
    #plot the subprefixes for the given prefix length
    for i in v:
        #store the baseline value for child nodes to compare against later
        baseline = int(i.addr.network_address)
        ipv6_ints.append(0)
        ipv6_masks.append(k)
        add_child_nodes(i, ipv6_masks, ipv6_ints, baseline, ax)

    plt.xlabel("Advertised Prefix Length")
    plt.ylabel("IPv6 Address Offset")
    ax.plot(ipv6_masks, ipv6_ints, 'r+', alpha=0)
    ax.set_ylim(bottom=0)

    ylocs, ylabels = plt.yticks()
    for i in range(len(ylocs)):
        print(ylocs[i])
        ylabels[i] = str(ipaddress.IPv6Address(int(ylocs[i])))
    plt.yticks(ylocs, ylabels)
    fig.suptitle("Relative offsets for subdomains allocated within /%d advertisement" % k)

    plt.savefig("offset_graphs/offset_%d.png" % k, bbox_inches="tight")
    plt.close()



