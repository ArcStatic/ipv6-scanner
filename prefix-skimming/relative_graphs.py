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
    
    plt.savefig("offset_graphs/offset_%d.png" % k, bbox_inches="tight")
    plt.close()

'''
    if v.addr.overlaps(ipaddress.IPv6Network("2001::/16")):
        ax1.add_patch(rect)
        ax1_ipv6_ints.append(int(v.addr.network_address))
        ax1_ipv6_masks.append(v.addr.prefixlen)
        add_child_nodes(v, ax1_ipv6_masks, ax1_ipv6_ints, ax1)
    elif v.addr.overlaps(ipaddress.IPv6Network("2400::/8")):
        ax2.add_patch(rect)
        ax2_ipv6_ints.append(int(v.addr.network_address))
        ax2_ipv6_masks.append(v.addr.prefixlen)
        add_child_nodes(v, ax2_ipv6_masks, ax2_ipv6_ints, ax2)
    elif v.addr.overlaps(ipaddress.IPv6Network("2600::/8")):
        ax3.add_patch(rect)
        ax3_ipv6_ints.append(int(v.addr.network_address))
        ax3_ipv6_masks.append(v.addr.prefixlen)
        add_child_nodes(v, ax3_ipv6_masks, ax3_ipv6_ints, ax3)
    elif v.addr.overlaps(ipaddress.IPv6Network("2800::/8")):
        ax4.add_patch(rect)
        ax4_ipv6_ints.append(int(v.addr.network_address))
        ax4_ipv6_masks.append(v.addr.prefixlen)
        add_child_nodes(v, ax4_ipv6_masks, ax4_ipv6_ints, ax4)
    elif v.addr.overlaps(ipaddress.IPv6Network("2a00::/8")):
        ax5.add_patch(rect)
        ax5_ipv6_ints.append(int(v.addr.network_address))
        ax5_ipv6_masks.append(v.addr.prefixlen)
        add_child_nodes(v, ax5_ipv6_masks, ax5_ipv6_ints, ax5)
    else:
        ax6.add_patch(rect)
        ax6_ipv6_ints.append(int(v.addr.network_address))
        ax6_ipv6_masks.append(v.addr.prefixlen)
        add_child_nodes(v, ax6_ipv6_masks, ax6_ipv6_ints, ax6)


#print("\n\nmin: %d\nmax: %d" % (min(ipv6_ints), max(ipv6_ints)))
#print("%d digits" % len(str(min(ipv6_ints))))
#print(len(ipv6_ints))

plt.xlabel("Advertised Prefix Length")
plt.ylabel("Set Values of Advertised IPv6 address")
plt.xlim((15, 65))
ax.plot(ipv6_masks, ipv6_ints, 'r+', alpha=0)


ax1.plot(ax1_ipv6_masks, ax1_ipv6_ints, 'r+', alpha=0)
ax2.plot(ax2_ipv6_masks, ax2_ipv6_ints, 'r+', alpha=0)
ax3.plot(ax3_ipv6_masks, ax3_ipv6_ints, 'r+', alpha=0)
ax4.plot(ax4_ipv6_masks, ax4_ipv6_ints, 'r+', alpha=0)
ax5.plot(ax5_ipv6_masks, ax5_ipv6_ints, 'r+', alpha=0)
ax6.plot(ax6_ipv6_masks, ax6_ipv6_ints, 'r+', alpha=0)



#convert y axis labels back to IPv6 addresses
for i in range(1,7):
    plt.subplot(6,1,i)

ylocs, ylabels = plt.yticks()
for i in range(len(ylocs)):
    ylabels[i] = str(ipaddress.IPv6Address(int(ylocs[i])))
plt.yticks(ylocs, ylabels)

plt.savefig("graphrelative.png", bbox_inches="tight")


#==================
#lines on figure
#spacing = 1.2
#figheight = (spacing * 10 + 1)
#fig = plt.figure(figsize=(4 / 1.5, figheight / 1.5))
fig = plt.figure(figsize=(50,50))
fontsize = 40
addr = "db8:2001::1"


# x, y vals: scale 0 - 1.0 (increase -> higher/to the right)
fig.text(0.5, 0.5, addr, size=fontsize, bbox=dict(facecolor="red", alpha=0.5))
#draw single line between points
l1 = lines.Line2D([0.1, 0.1], [0, 1], lw=5, transform=fig.transFigure, figure=fig)
fig.lines.extend([l1])

fig.savefig("matplot.png")
'''




