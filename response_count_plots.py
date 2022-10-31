import sys
import matplotlib.pyplot as plt
import numpy as np

class AddrResponses:
    addr = ""
    echo_req = 0
    echo_reply = 0
    time_exceeded = 0
    no_route = 0
    addr_unreachable = 0
    admin_prohibited = 0
    port_unreachable = 0
    reject_route = 0
    failed_policy = 0
    total_responses = 0

    def __str__(self):
        results = []
        results.append(f'addr: {self.addr}') 
        results.append(f'echo_req: {self.echo_req}') 
        results.append(f'echo_reply: {self.echo_reply}') 
        results.append(f'time_exceeded: {self.time_exceeded}') 
        results.append(f'no_route: {self.no_route}') 
        results.append(f'addr_unreachable: {self.addr_unreachable}') 
        results.append(f'admin_prohibited: {self.admin_prohibited}') 
        results.append(f'port_unreachable: {self.port_unreachable}') 
        results.append(f'reject_route: {self.reject_route}') 
        results.append(f'failed_policy: {self.failed_policy}') 
        results.append(f'total_responses: {self.total_responses}')
        return '\n'.join(results)




def addr_array(input_file):
    addrs = []
    line = input_file.readline()
    while line != '':
        if '::' in line:
            new_addr = AddrResponses()
            #print(line[:-1])
            new_addr.addr = line[:-1]
            new_addr.echo_req = int((input_file.readline().split(": "))[1][:-1])
            new_addr.echo_reply = int((input_file.readline().split(": "))[1][:-1])
            new_addr.time_exceeded = int((input_file.readline().split(": "))[1][:-1])
            new_addr.no_route = int((input_file.readline().split(": "))[1][:-1])
            new_addr.address_unreachable = int((input_file.readline().split(": "))[1][:-1])
            new_addr.admin_prohibted = int((input_file.readline().split(": "))[1][:-1])
            new_addr.port_unreachable = int((input_file.readline().split(": "))[1][:-1])
            new_addr.reject_route = int((input_file.readline().split(": "))[1][:-1])
            new_addr.failed_policy = int((input_file.readline().split(": "))[1][:-1])
            
            new_addr.total_responses = int((input_file.readline().split(": "))[1][:-1])
            

            #print("req: ", req, "addr: ", new_addr.addr)
            addrs.append(new_addr)
        line = input_file.readline()
    return addrs




resp_file = open(sys.argv[1], "r")
addrs = addr_array(resp_file)


echo_replies_arr = []
time_exceeded_arr = []
no_route_arr = []
addr_unreachable_arr = []
admin_unreachable_arr = []
port_unreachable_arr = []
reject_route_arr = []
policy_failed_arr = []
total_responses_arr = []

for obj in addrs:
    echo_replies_arr.append(obj.echo_reply)
    time_exceeded_arr.append(obj.time_exceeded)
    no_route_arr.append(obj.no_route)
    addr_unreachable_arr.append(obj.address_unreachable)
    admin_unreachable_arr.append(obj.admin_prohibited)
    port_unreachable_arr.append(obj.port_unreachable)
    reject_route_arr.append(obj.reject_route)
    policy_failed_arr.append(obj.failed_policy)
    total_responses_arr.append(obj.total_responses)



plt.hist(echo_replies_arr)
plt.title("Echo Replies received from /48 Advertisements")
plt.xlabel("Number of responses")
plt.ylabel("Number of advertisements")
plt.savefig("echo_replies.jpg")
plt.close()

plt.hist(time_exceeded_arr)
plt.title("Time Exceeded responses received from /48 Advertisements")
plt.xlabel("Number of responses")
plt.ylabel("Number of advertisements")
plt.savefig("time_exceeded.jpg")
plt.close()

plt.hist(no_route_arr)
plt.title("No Route responses received from /48 Advertisements")
plt.xlabel("Number of responses")
plt.ylabel("Number of advertisements")
plt.savefig("no_route.jpg")
plt.close()

plt.hist(addr_unreachable_arr)
plt.title("Address Unreachable responses received from /48 Advertisements")
plt.xlabel("Number of responses")
plt.ylabel("Number of advertisements")
plt.savefig("addr_unreachable.jpg")
plt.close()

plt.hist(admin_unreachable_arr)
plt.title("Admin Prohibited responses received from /48 Advertisements")
plt.xlabel("Number of responses")
plt.ylabel("Number of advertisements")
plt.savefig("admin_prohibited.jpg")
plt.close()

plt.hist(port_unreachable_arr)
plt.title("Port Unreachable responses received from /48 Advertisements")
plt.xlabel("Number of responses")
plt.ylabel("Number of advertisements")
plt.savefig("port_unreachable.jpg")
plt.close()

plt.hist(reject_route_arr)
plt.title("Reject Route responses received from /48 Advertisements")
plt.xlabel("Number of responses")
plt.ylabel("Number of advertisements")
plt.savefig("reject_route.jpg")
plt.close()

plt.hist(policy_failed_arr)
plt.title("Failed Ingress/Egress Policy received from /48 Advertisements")
plt.xlabel("Number of responses")
plt.ylabel("Number of advertisements")
plt.savefig("failed_policy.jpg")
plt.close()

plt.hist(total_responses_arr)
plt.title("Total Responses received from /48 Advertisements")
plt.xlabel("Number of responses")
plt.ylabel("Number of advertisements")
plt.savefig("total_responses.jpg")
plt.close()




responsive = 0
non_responsive = 0
r_100 = 0
r_500 = 0
r_1000 = 0
r_5000 = 0
r_10000 = 0
r_max = 0

for i in range(len(addrs)):
    if addrs[i].total_responses == 0:
        non_responsive += 1
    elif (addrs[i].total_responses > 0) and (addrs[i].total_responses <= 100):
        r_100 += 1
    elif (addrs[i].total_responses > 100) and (addrs[i].total_responses <= 500):
        r_500 += 1
    elif (addrs[i].total_responses > 500) and (addrs[i].total_responses <= 1000):
        r_1000 += 1
    elif (addrs[i].total_responses > 1000) and (addrs[i].total_responses <= 5000):
        r_5000 += 1
    elif (addrs[i].total_responses > 5000) and (addrs[i].total_responses <= 10000):
        r_10000 += 1
    else:
        r_max += 1








print("0: %d\n1-100: %d\n101-500: %d\n501-1000: %d\n1001-5000: %d\n5001-10,000: %d\n10,001+: %d" % (non_responsive, r_100, r_500, r_1000, r_5000, r_10000, r_max));

