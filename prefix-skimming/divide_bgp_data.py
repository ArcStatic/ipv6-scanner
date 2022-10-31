import sys
import random


def write_scan_file(input_file, output_file):
    output_file.write("mkdir scan_pcaps_`date +%F`_2000\n")
    output_file.write("sudo nohup tcpdump ip6 host 2001:630:40:f00::f:251 -n -G 3600 -w scan_pcaps_`date +%F`_2000/%d-%m-%y-%H-%M-%S.pcap -Z root &\n\n")

    cmd_base = "sudo nohup ./c_scanner 2001:630:40:f00::f:251"

    for line in input_file.readlines():
        output_file.write("{cmd} {dst} &\n".format(cmd=cmd_base, dst=line[:-1]))

    input_file.close()
    output_file.close()



input_file = open(sys.argv[1], "r")
data = input_file.readlines()
random.shuffle(data)
file_count = 1
adv_count = 0

output_file = open("scan_candidates_{num}.txt".format(num=file_count), "w+")

for adv in data:
    output_file.write(adv)
    adv_count += 1
    if adv_count == 2000: 
        output_file.close()
        write_scan_file(open("scan_candidates_{num}.txt".format(num=file_count), "r"), open("scan_script_{num}.sh".format(num=file_count), 'w+'))
        file_count += 1
        output_file = open("scan_candidates_{num}.txt".format(num=file_count), "w+")
        adv_count = 0
        






