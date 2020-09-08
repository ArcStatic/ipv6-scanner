import matplotlib.pyplot as plt
import matplotlib.transforms as mtransforms
import matplotlib.patches as patch
import matplotlib.lines as lines
import sys
import ipaddress

from prefix_filter import process_data

def add_child_nodes(node, x_list, y_list):
    for i in node.children:
        print("child node added")
        x_list.append(node.addr.prefixlen)
        y_list.append(int(node.addr.network_address))
        add_child_nodes(i, x_list, y_list)

#===================
#plot points w/ data
root_nodes = process_data(sys.argv[1])
ipv6_ints = []
ipv6_masks = []

fig = plt.figure(figsize=(12,20))
ax = fig.add_subplot(111)
#fig,ax = plt.subplots(1)

for k, v in root_nodes.items():
    print("%s: %d" % (k,int(v.addr.network_address)))
    print("Final addr in block: %s" % v.addr[-1])
    print("Gap: %d\n" % (int(v.addr[-1]) - int(v.addr.network_address)))
    #create a rectangle which encompasses all possible addresses which could be allocated within a given advertisement
    #v.addr[-1] is the last valid address in a range (ie. all free bits set to 1/free hex values set to f)
    rect = patch.Rectangle((v.addr.prefixlen, int(v.addr.network_address)), (128 - v.addr.prefixlen), (int(v.addr[-1]) - int(v.addr.network_address)), alpha=0.4, color="red")
    ax.add_patch(rect)
    ipv6_ints.append(int(v.addr.network_address))
    ipv6_masks.append(v.addr.prefixlen)
    add_child_nodes(v, ipv6_masks, ipv6_ints)



print("\n\nmin: %d\nmax: %d" % (min(ipv6_ints), max(ipv6_ints)))
print("%d digits" % len(str(min(ipv6_ints))))
print(len(ipv6_ints))

plt.xlabel("Advertised Prefix Length")
plt.ylabel("Set Values of Advertised IPv6 address")
plt.xlim((15, 65))

plt.plot(ipv6_masks, ipv6_ints, 'r+', alpha=0)

ylocs, ylabels = plt.yticks()


for i in range(len(ylocs)):
    ylabels[i] = str(ipaddress.IPv6Address(int(ylocs[i])))

plt.yticks(ylocs, ylabels)

plt.savefig("graphreduced.png", bbox_inches="tight")

'''
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




