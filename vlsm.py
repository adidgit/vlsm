#!/usr/bin/python
import re
from ipcalc import IP, Network
import argparse
import math
import sys

def check_cidr(cidr):
    """
    Check CIDR notation
    """
    cidr_regex = r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$'
    if not re.match(cidr_regex, cidr):
        raise argparse.ArgumentTypeError("Input %s not valid CIDR notation. Example: 192.168.1.0/24" % cidr)
    return cidr
    
def check_hosts(hosts):
    """
    Check Needed hosts
    """
    try:
        hosts = int(hosts)
        if hosts < 1:
            raise argparse.ArgumentTypeError("Number of needed available hosts can't be less than 1")
    except ValueError:
        raise argparse.ArgumentTypeError("Number of needed available hosts must be integer")
    return hosts

def print_net_info(net,net_id):
    """
    Print detailed net info if it has been requested
    """
    print('===========')
    print(net_id)
    print('===========')
    print('ip address: {0}'.format(net))
    print('to ipv6...: {0}'.format(net.to_ipv6()))
    print('ip version: {0}'.format(net.version()))
    print('ip info...: {0}'.format(net.info()))
    print('subnet....: {0}'.format(net.subnet()))
    print('num ip\'s..: {0}'.format(net.size()))
    print('integer...: {0}'.format(int(net)))
    print('hex.......: {0}'.format(net.hex()))
    print('netmask...: {0}'.format(net.netmask()))
    print('wildcard..: {0}'.format(wildcard(net.netmask())))
    # Not implemented in IPv6
    if net.version() == 4:
        print('network...: {0}'.format(net.network()))
        print('broadcast.: {0}'.format(net.broadcast()))
    print('first host: {0}'.format(net.host_first()))
    print('reverse...: {0}'.format(net.host_first().to_reverse()))
    print('last host.: {0}'.format(net.host_last()))
    print('reverse...: {0}'.format(net.host_last().to_reverse()))

def wildcard(netmask):
    octet_subnet = [int(j) for j in str(netmask).split(".")]
    wild_mask = []
    for i in octet_subnet:
        wild_bit = 255 - i
        wild_mask.append(wild_bit)
        wildcard = ".".join([str(i) for i in wild_mask])
    return wildcard

def calc_subnets(major_net,hosts):
    """
    Calculate subnets 
    """
    subnets = []                                                                # List will be used to store Network objects 
    start_ip=major_net.network()                                                # Starting ip is the major network ip
    for h in hosts:
        new_netmask = 0
        host_bits= int(math.ceil(math.log(h+2,2)))                              # Host bits = Log2(Number-of-hosts) +2  (+2 is for network and broadcast)
        new_netmask= 32 - host_bits                                             # IPv4 addresses are 32 bits wide - Subtract hosts bits from 32 to 
                                                                                # calculate the minimum subnet prefix for each subnet
        subnet = Network(str(start_ip),new_netmask)
        subnets.append([subnet,h])                                              # Store the subnet and the number of needed hosts to return to main function
        new_start_ip =str(subnet.broadcast())                                   # Find the next subnet start ip
        ip_t=IP(new_start_ip)                                                   #
        start_ip=ip_t + 1                                                       # Very useful __add__ from ipcalc module 
    return subnets

    
def print_subnets(subnet,hosts,subnet_id):
    """
    Print the subnets info
    """
    p = []
    p.append(subnet_id)
    p.append(hosts)
    p.append(subnet.size() - 2)
    p.append(subnet.size() - 2 - hosts)
    p.append((hosts * 100) / (subnet.size() - 2))
    p.append(subnet.network())
    p.append(subnet.host_first())
    p.append(subnet.host_last())
    p.append(subnet.broadcast())
    p.append(subnet.subnet())
    p.append(subnet.netmask())
    p.append('|')
    p.append('-')
    p.append('/')
    p.append('%')

    print('{d[0]:^11}{d[11]}{d[11]}\
{d[1]:>10}{d[11]}\
{d[2]:>10}{d[11]}\
{d[3]:>10}{d[11]}\
{d[4]:>4}{d[14]:<2}{d[11]}{d[11]}\
{d[5]:^17}{d[11]}\
{d[6]:<17}{d[12]:^3}{d[7]:>15}{d[11]}\
{d[8]:^17}{d[11]}\
{d[13]:>2}{d[9]:<3}{d[11]}\
{d[10]:^17}{d[11]}'\
.format(d=p))
       

def print_warning():
    """
    Print a warning in case needed subnets and hosts per subnet does not fit inside the network
    """
    print
    print ('!' * 149)
    print "!!!Warning!!! The needed subnets and hosts per subnet does NOT fit inside the network. Below is a setup you could consider!!!!!!!!!!!"
    print ('!' * 149)
    print

def print_header():
    """
    Print the header
    """
    print ('=' * 149)
    p = ['', 'Hosts', 'Network','|']
    t = ['Subnet', 'Needed', 'Available ','Spare','Usage','Network Address','Usable Address Range','Broadcast',' /','Mask','|']
    print('{d[0]:11}{d[3]}{d[3]}{d[1]:^39}{d[3]}{d[3]}{d[2]:^95}{d[3]}'.format(d=p))
    print('=' * 149)
    print('{d[0]:^11}{d[10]}{d[10]}{d[1]:^10}{d[10]}{d[2]:^10}{d[10]}{d[3]:^10}{d[10]}{d[4]:^6}{d[10]}{d[10]}{d[5]:^17}{d[10]}{d[6]:^35}{d[10]}{d[7]:^17}{d[10]}{d[8]:^5}{d[10]}{d[9]:^17}{d[10]}'.format(d=t))
    print('-' * 149)

def print_footer(ip,ip_in_subnets):
    """
    Print if initial ip found within any subnet or not
    """
    print('-' * 149)
    if ip_in_subnets == True:
        print "* Subnet containing the initial ip %s " %(ip)
    else:
        print "No subnet contains the initial ip"
    print('=' * 149)
    print


        
if __name__ == '__main__':
    """
    Main
    """
    parser = argparse.ArgumentParser(description='Variable Length Subneting',epilog='Example of use: ./vlsm.py 192.168.1.0/24 10 10 100')    #
    parser.add_argument('cidr', metavar='CIDR', type=check_cidr, nargs=1,                                                                    #
                        help='CIDR notation i.e 192.168.1.10/24')                                                                            # Argument Parser
    parser.add_argument('hosts', metavar='num', type=check_hosts, nargs='+',                                                                 #
                        help='number of needed hosts per subnet (excluding network and broadcast address)')                                  #
    parser.add_argument('-v', action="store_true", default=False, help='print detailed info for network and subnets)')                       #
    args = parser.parse_args()                                                                                                               #
                                                                                                                

    hosts=sorted(args.hosts, key=int, reverse=True)                             # Sort the needed hosts descending - Subnets are always calculated from largest need hosts to smallest 
    ip = args.cidr[0].split("/")[0]                                             # 192.168.1.0/24 -> 192.168.1.0
    netmask = int(args.cidr[0].split("/")[1])                                   # 192.168.1.0/24   ->  24
    
    major_net = Network(ip, netmask)                                            # Initial network
    
    subnets = calc_subnets(major_net,hosts)                                     # Calculate the subnets based on the initial network and number of hosts needed

    if args.v == True :
        print_net_info(major_net,"Network")
        i=1
        for subnet in subnets:
            print_net_info(subnet[0],"SUBNET_"+str(i))
            i += 1

    total_subnet_hosts =0                                                       #
    for subnet in subnets:                                                      # The requested subnets 
        total_subnet_hosts += subnet[0].size()                                  # may not have fitted 
                                                                                # so print a working solution if so
    if total_subnet_hosts > major_net.size() :                                  #
        print_warning()                                                         #


    print_header()
    id = 1
    ip_in_subnets = False
    for subnet in subnets:
        if subnet[0].has_key(ip) ==True:
            print_subnets(subnet[0],subnet[1],"*"+str(id))                      #Add an asterisk in the subnet if it contains the initial ip 
            ip_in_subnets = True
        else:
            print_subnets(subnet[0],subnet[1],str(id))
        id += 1
    print_footer(ip,ip_in_subnets)





