import sys
from pprint import pprint

class AdvertStats:
    def __init__(self):
        self.addr = 0
        self.echo_req = 0
        self.echo_reply = 0
        self.addr_unreach = 0
        self.time_exceeded = 0
        self.no_route = 0
        self.admin_prohibited = 0
        self.port_unreach = 0
        self.reject_route = 0
        self.failed_policy = 0
        self.duplicates = 0
        self.total_responses = 0
        self.mask_length = 0

class AdvertTotals:
    def __init__(self):
        self.echo_req = 0
        self.echo_reply = 0
        self.addr_unreach = 0
        self.time_exceeded = 0
        self.no_route = 0
        self.admin_prohibited = 0
        self.port_unreach = 0
        self.reject_route = 0
        self.failed_policy = 0
        self.duplicates = 0
        self.no_resp = 0
        self.total_ads = 0


def count_adverts(adv_list):
    adv_totals = AdvertTotals()
    for adv in adv_list:
        resp = False
        if adv.echo_req > 0:
            adv_totals.echo_req += 1
        if adv.echo_reply > 0:
            adv_totals.echo_reply += 1
            resp = True
        if adv.addr_unreach > 0:
            adv_totals.addr_unreach += 1
            resp = True
        if adv.time_exceeded > 0:
            adv_totals.time_exceeded += 1
            resp = True
        if adv.no_route > 0:
            adv_totals.no_route += 1
            resp = True
        if adv.admin_prohibited > 0:
            adv_totals.admin_prohibited += 1
            resp = True
        if adv.port_unreach > 0:
            adv_totals.port_unreach += 1
            resp = True
        if adv.reject_route > 0:
            adv_totals.reject_route += 1
            resp = True
        if adv.failed_policy > 0:
            adv_totals.failed_policy += 1
            resp = True
        if adv.duplicates > 0:
            adv_totals.duplicates += 1
        adv_totals.total_ads += 1
        if resp is False:
            adv_totals.no_resp += 1

    return adv_totals


#TODO: get sent echo_req count for each advertisement for this
#def response_percentages(adv_list):
#    for adv in adv_list:
        



def process_advertisements(f):
    adv = None
    adv_list = []
    for line in f:
        if "Advertised range" in line:
            adv = AdvertStats()
            #TODO: add new elif to add different mask lengths
            #Current C output assumes every advert is a /48
            line = line.split(": ")
            adv.addr = line[1][:-1]
            adv.mask_length = 48
        elif "total_resp_count" in line:
            line = line.split(": ")
            adv.total_responses = int(line[1][:-1])
        elif "echo_req_count" in line:
            line = line.split(": ")
            adv.echo_req = int(line[1][:-1])
        elif "echo_reply_count" in line:
            line = line.split(": ")
            adv.echo_reply = int(line[1][:-1])
        elif "address_unreachable_count" in line:
            line = line.split(": ")
            adv.addr_unreach = int(line[1][:-1])
        elif "time_exceeded_count" in line:
            line = line.split(": ")
            adv.time_exceeded = int(line[1][:-1])
        elif "no_route_count" in line:
            line = line.split(": ")
            adv.no_route = int(line[1][:-1])
        elif "admin_prohibited_count" in line:
            line = line.split(": ")
            adv.admin_prohibited = int(line[1][:-1])
        elif "port_unreachable_count" in line:
            line = line.split(": ")
            adv.port_unreach = int(line[1][:-1])
        elif "reject_route_count" in line:
            line = line.split(": ")
            adv.reject_route = int(line[1][:-1])
        elif "failed_policy_count" in line:
            line = line.split(": ")
            adv.failed_policy = int(line[1][:-1])
        #duplicate count is the last item per adv entry in C output
        elif "duplicate_count" in line:
            line = line.split(": ")
            adv.duplicates = int(line[1][:-1])
            adv_list.append(adv)

    return adv_list



f = open(sys.argv[1], "r")
ads = process_advertisements(f)
f.close()
#response_percentages(ads)
totals = count_adverts(ads)
pprint(vars(totals))
    
