import matplotlib.pyplot as plt
import numpy as np
import sys

msg_types = []
instances = []

#process input
f = open(sys.argv[1], "r")
for line in f:
    #item = f.readline()
    print(line)
    if "final count" not in line:
        vals = line[6:].split(" count: ")
        #print(vals)
        msg_types.append(vals[0])
        instances.append(int(vals[1][:-1]))

print(msg_types)
print(instances)

f.close()


#plot graph
#fig = plt.figure()
#ax = fig.add_axes([0,0,1,1])
#ax.bar(msg_types, instances)
#plt.show()
#plt.savefig("testimg.png")

plt.style.use('ggplot')
x_pos = [i for i, _ in enumerate(msg_types)]
plt.bar(x_pos, instances, color='green')
plt.xlabel("ICMPv6 Message Type")
plt.ylabel("# of instances")
plt.title("ICMPv6 Responses Received in Initial Scan")

plt.xticks(x_pos, msg_types)

plt.savefig("testimgnew.png")


