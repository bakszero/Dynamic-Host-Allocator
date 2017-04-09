#!/usr/bin/env python

from math import pow, ceil, log
from sys import argv
import re


def min_pow2(x):  # how many bits do we need to borrow
    z = log(x, 2)  # to cover number of hosts
    if int(z) != z:  # in math language:
        z = ceil(z)  # to which integer power do
    return int(z)  # we need to raise 2 to get the number that is ge "x"


def getmask(cidr):  # ex. 24 -> 255.255.255.0
    arr = [0 for i in range(4)]  # creating list of four 0s
    y = int(cidr / 8)  # how many octets of 255
    if y > 0:  # if mask < 8
        for z in range(y):
            arr[z] = 255
        arr[z + 1] = int(256 - pow(2, 8 - (cidr - 8 * y)))
    else:
        arr[0] = 256 - pow(2, 8 - cidr)
    return arr


def getnet(ipaddr, nmask):  # Get network address from ip and mask
    net = [0 for i in range(4)]
    for i in range(4):
        print ipaddr
        print nmask
        net[i] = int(ipaddr[i]) & int(nmask[i])  # octet and mask
    return net


def getfirst(ipaddr):  # Get first usable address from ip and mask
    addr = ipaddr[:]  # list is mutable, not to change the global value
    addr[3] = int(addr[3]) + 1
    return addr


def getlast(ipaddr, nmask):  # Get last usable address from ip and mask
    addr = getbcast(ipaddr, nmask)
    addr[3] -= 1
    return addr


def getbcast(ipaddr, nmask):  # Get broadcast address from ip and mask
    net = [0 for i in range(4)]
    for i in range(4):
        net[i] = int(ipaddr[i]) | 255 - int(nmask[i])  # octet or wildcard mask
    return net


def getnextaddr(ipaddr, nmask):
    ipaddr = getbcast(ipaddr, nmask)
    for i in range(4):
        if ipaddr[3 - i] == 255:
            ipaddr[3 - i] = 0
            if ipaddr[3 - i - 1] != 255:
                ipaddr[3 - i - 1] += 1
                break
        else:
            ipaddr[3 - i] += 1
            break
    return ipaddr


def norm(ipaddr):
    print "ipaddr is "
    print ipaddr
    addr = ipaddr[:]
    print "addr is "
    print (addr)
    for i in range(len(addr)):
        addr[i] = str(addr[i])
    return ".".join(addr)


def vlsm(ipaddr, hosts):
    global need, allc
    bits = 0

    for x in range(len(hosts)):
        bits = min_pow2(hosts[x] + 2)
        ipaddr = getnet(ipaddr, getmask(int(32 - bits)))

        print " SUBNET: %d NEEDED: %3d (%3d %% of) ALLOCATED %4d ADDRESS: %15s :: %15s - %-15s :: %15s MASK: %d (%15s)" % \
              (x + 1,
               hosts[x],
               (hosts[x] * 100) / (int(pow(2, bits)) - 2),
               int(pow(2, bits)) - 2,
               norm(ipaddr),
               norm(getfirst(ipaddr)),
               norm(getlast(ipaddr, getmask(int(32 - bits)))),
               norm(getbcast(ipaddr, getmask(int(32 - bits)))),
               32 - bits,
               norm(getmask(int(32 - bits))))

        need += hosts[x]
        allc += int(pow(2, bits)) - 2
        ipaddr = getnextaddr(ipaddr, getmask(int(32 - bits)))


if argv[1] == "-h" or argv[1] == "--help":
    print
    print "Usage: vlsm.py <ipv4_address/mask> <num_hosts1> [num_hosts2 num_hosts3 ...]"
    print "Subnets the initiallly provided network into subnetworks by the number of hosts needed in each."
    print
    exit(0)

good = re.match("^(?:(?:(?:2[0-5][0-5]|1\d{2}|\d{2}|\d)\.){3}(?:[12]\d{2}|\d{2}|\d)\/(?:3[0-2]|[1-2]\d|\d))\
(?:\ \d*)+$", " ".join(argv[1:]))

if good == None:
    exit("ERROR: Validate the input")

ip = argv[1].split("/")[0].split(".")   # 192.168.1.0/24 2 8 22 54  -> list of str ['192','168','1','0']
cidr = int(argv[1].split("/")[1])       # 192.168.1.0/24 2 8 22 54  -> str 24
arg = [0 for i in range(len(argv[2:]))] #                2 8 22 54  -> list of str ['2','8','22','54']
mask = getmask(cidr)                    #                       24  -> list of int [255,255,255,0]

print ("MASK IS :")
print mask
print ("type of mask is ")
print type(mask)
total_hosts = 0

for x in range(len(ip)):  # list of str ['192','168','1','0'] ->
    ip[x] = int(ip[x])  # list of int [192,168,1,0]

for x in range(len(argv[2:])):  # list of str ['2','8','22','54'] ->
    arg[x] = int(argv[x + 2])  # list of int [2,8,22,54]

for x in range(len(argv[2:])):
    total_hosts += int(argv[2:][x])
print ("TOTAL HOSTS ARE :")
print total_hosts
if total_hosts > (pow(2, 32 - cidr) - 2):
    exit("ERROR: Too many hosts")

arg = sorted(arg, reverse=True)  # sort (descending) list [2,8,22,54] -> [54,22,8,1]

need = 0
allc = 0

print
vlsm(getnet(ip, mask), arg)
print

print
print " STATISTICS"
print " =========="
print " Major Network: %s/%d" % (norm(getnet(ip, mask)), cidr)
print " Available IP addresses in major network: %d" % (pow(2, 32 - cidr) - 2)
print " Number of IP addresses needed: ", need
print " Available IP addresses in allocated subnets: ", allc
print " About %d%% of available major network address space is used" % (
    ((allc + (len(arg) * 2)) * 100) / (pow(2, 32 - cidr)))
print " About %d%% of subnetted network address space is used" % (need * 100 / allc)
print