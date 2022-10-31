import sys
import random

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
        file_count += 1
        output_file = open("scan_candidates_{num}.txt".format(num=file_count), "w+")
        adv_count = 0
        

