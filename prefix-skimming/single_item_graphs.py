import matplotlib.pyplot as plt
import matplotlib.transforms as mtransforms
import matplotlib.patches as patch
import matplotlib.lines as lines
import sys
import ipaddress

from prefix_filter import process_data

def add_child_nodes(node, x_list, y_list, baseline, ax):
    for i in node.children:
        print("%s" % (i.addr))
        rect = patch.Rectangle((i.addr.prefixlen, int(i.addr.network_address)), (128 - i.addr.prefixlen), (int(i.addr[-1]) - int(i.addr.network_address)), alpha=0.2, color="red")
        ax.add_patch(rect)
        x_list.append(node.addr.prefixlen)
        y_list.append(int(node.addr.network_address))
        add_child_nodes(i, x_list, y_list, baseline, ax)

#===================
#plot points w/ data
root_nodes = process_data(sys.argv[1])

for k, v in root_nodes.items():
    #print("%s: %d" % (k,int(v.addr.network_address)))
    #print(str(int(v.addr.network_address))[:6])
    #only plot for root prefixes which have associated subprefixes
    if v.children:
        fig = plt.figure()
        ax = fig.add_subplot(111)
        ipv6_ints = []
        ipv6_masks = []
        print("\n======\n%s" % v.addr)
        #create a rectangle which encompasses all possible addresses which could be allocated within a given advertisement
        #v.addr[-1] is the last valid address in a range (ie. all free bits set to 1/free hex values set to f)
        #y-axis is the offset from the lowest possible address value in this address range (ie. the range permitted by the root/largest advertisement given)
        #ie. the canvas is effectively a rectangle showing the space of the largest advertisement in the chain
        rect = patch.Rectangle((v.addr.prefixlen, int(v.addr.network_address)), (128 - v.addr.prefixlen), (int(v.addr[-1]) - int(v.addr.network_address)), alpha=0.2, color="red")
        #store the baseline value for child nodes to compare against later
        baseline = int(v.addr.network_address)
        ax.add_patch(rect)
        add_child_nodes(v, ipv6_masks, ipv6_ints, baseline, ax)

        plt.xlabel("Advertised Prefix Length")
        plt.ylabel("IPv6 Address Ranges")
        #plt.xlim((15, 65))
        ax.plot(ipv6_masks, ipv6_ints, 'r+', alpha=0)

        ylocs, ylabels = plt.yticks()
        for i in range(len(ylocs)):
            ylabels[i] = str(ipaddress.IPv6Address(int(ylocs[i])))
        plt.yticks(ylocs, ylabels)

        fig.suptitle("Address spaces allocated within BGP advertisement %s" % str(v.addr))

        plt.savefig("offset_graphs/%s.png" % str(k).replace(":","-").replace("/",""), bbox_inches="tight")
        plt.close()



