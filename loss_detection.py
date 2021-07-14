import filecmp
import sys

#check if same number of replies received compared to packets sent
def check_eq_linecount(f1, f2):
    if len(f1) == len(f2):
        return True
    else:
        return False

def check_response_eq(send_f, recv_f):
    sent_pkts = []
    recv_pkts = []
    for sent_item in send_f:
        sent_pkts.append(sent_item.split(",")[0][4:])
    for recv_item in recv_f:
        recipient_addr = recv_item.split(",")[0]
        recv_pkts.append(recipient_addr.split(" ")[2])
    print("sent_pkts: {sent}\n\nrecv_pkts: {recv}".format(sent=sent_pkts, recv=recv_pkts))
    for item in sent_pkts:
        if item in recv_pkts:
            print("Response received from %s" % item)
        else:
            print("No response received for %s" % item)

#remove this, just here for familiarity for now
#use to check if losses are consistent
def check_same_output(f1, f2):
    if filecmp.cmp(f1, f2):
        return True
    else:
        return False

def check_loss_between_files(f1, f2):
    consistent_loss_pattern = False
    if check_eq_linecount(f1, f2):
        #TODO: change to check_loss_between_files with X+1 rates (ie. loop through dir)
        return True
    if check_same_output(f1, f2):
        consistent_loss_pattern = True

sent = open(sys.argv[1], "r")
recv = open(sys.argv[2], "r")
check_response_eq(sent, recv)
