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
#fig = plt.figure(figsize=(12,50))
#fig = plt.figure()
#ax = fig.add_subplot(111)
root_nodes = process_data(sys.argv[1])

'''
ax1_ipv6_ints = []
ax1_ipv6_masks = []
ax2_ipv6_ints = []
ax2_ipv6_masks = []
ax3_ipv6_ints = []
ax3_ipv6_masks = []
ax4_ipv6_ints = []
ax4_ipv6_masks = []
ax5_ipv6_ints = []
ax5_ipv6_masks = []
ax6_ipv6_ints = []
ax6_ipv6_masks = []

ax1 = fig.add_subplot(611)
ax2 = fig.add_subplot(612)
ax3 = fig.add_subplot(613)
ax4 = fig.add_subplot(614)
ax5 = fig.add_subplot(615)
ax6 = fig.add_subplot(616)
'''
#ipv6_ints = []
#ipv6_masks = []


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

        plt.savefig("offset_graphs/%s.png" % str(k).replace(":","-").replace("/",""), bbox_inches="tight")
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




