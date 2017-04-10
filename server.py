import sys
import os
import re
import socket
from math import *
from operator import itemgetter
import copy
import socket


PORT = 1451
HOST = 'localhost'
allocation = {}
mac_map = {}


def validate_CIDR(CIDR_format_string):

    valid_IP_regex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"

    CIDR_format_string = CIDR_format_string.split('/')
    ip = CIDR_format_string[0]
    subnet_mask = CIDR_format_string[1]

    if not re.match(valid_IP_regex, ip):
        print ("Invalid IPv4 has been provided.")

    try:
        subnet_mask = int(subnet_mask)
    except TypeError as err:
        print("Type Error: {0}".format(err))
        sys.exit(1)

    if not subnet_mask < 33:
        print ("Invalid Subnet Mask has been provided.")
        sys.exit(1)



def convert_mask_to_ip(subnet_mask):
    
    # ex. 24 -> 255.255.255.0
    
    subnet_list = []
    for x in xrange(4): # creating list of four 0s
        subnet_list.append(0)
    
    #print (subnet_list)
    try:
        octets = int(subnet_mask / 8)  # how many octets of 255
    except TypeError as err:
        print ("Type Error for your Subnet Mask provided: {0}".format(err))
        sys.exit(1)

    if (octets <= 0):
        rem_subnet = 8 - subnet_mask
        #Fixed an int function
        subnet_list[0] = int(256 - pow(2,rem_subnet))

    else:
        for i in xrange(octets):
            subnet_list[i] = 255
        rem_subnet = 8 - (subnet_mask - 8 * octets)
        subnet_list[i+1] = int(256 - pow(2,rem_subnet))
    
    return subnet_list


def check_lab_capacity(capacity_of_labs, subnet_mask):
    
    total_capacity = 0
    for i in capacity_of_labs:
        total_capacity += i

    # Check if lab capacity is valid. If not, raise an error.
    if total_capacity > (pow(2, 32 - int(subnet_mask)) - 2):
        exit("ERROR: Too many hosts")
    else:
        return total_capacity


def get_network_address(ip_addr,subnet_list):
    
    NA=[]
    for x in xrange(4):
        NA.append(0)
    
    # Convert list members to ints.
    for x in xrange(4):
        ip_addr[x] = int(ip_addr[x])
        subnet_list[x] = int(subnet_list[x])
    for x in range(4):
        
        # Logic: NA is obtained via ANDing the bits of ip address and the subnet
        
        NA[x] = ip_addr[x] & subnet_list[x]  # octet and subnetmask
    return NA


def get_broadcast_address(ip_addr, subnet_list):

    # Get broadcast address from ip and mask

    BA = []
    for x in xrange(4):
        BA.append(0)
    
    # Convert list members to ints.
    
    for x in xrange(4):
        ip_addr[x] = int(ip_addr[x])
        subnet_list[x] = int(subnet_list[x])
    
    for x in xrange(4):
        #Logic: You OR!
        BA[x] = (ip_addr[x]) | (255 - subnet_list[x])  # octet or wildcard mask
    return BA


def min_pow2(capacity):
    
    # how many bits do we need to borrow to cover number of hosts

    z = log(capacity, 2)  
    int_z = int(z)
    if z == int_z:
        return int_z
    else:
        return int(ceil(z))
    

def join(ip_addr):

    # Joiner for the IP

    addr = []
    for i in xrange(len(ip_addr)):
        addr.append(str(ip_addr[i]))
    #print addr
    addr =  ".".join(addr)

    return addr


def get_next_usable_addr(ipaddr, subnet_list):
    
    """
    Isn't this a duplicate of get_next_ip_addr(ipaddr)?
    """

    ipaddr = get_broadcast_address(ipaddr, subnet_list)
    
    for i in xrange(len(ipaddr)):
        last_digit = 3-i
        if ipaddr[last_digit] != 255:
            ipaddr[last_digit] += 1
            break
        else:
            ipaddr[last_digit] = 0
            if ipaddr[last_digit - 1] != 255:
                ipaddr[last_digit - 1] += 1
                break
    return ipaddr


def get_next_ip_addr(ipaddr):
    
    """
    Gives the next IPv4 addr.

    >>> get_next_ip_addr('10.220.65.66')
    >>> '10.220.65.67'
    """

    ipaddr = ipaddr.split('.')

    for i in xrange(len(ipaddr)):
        ipaddr[i] = int(ipaddr[i])

    for i in xrange(len(ipaddr)):
        last_digit = 3-i
        if ipaddr[last_digit] != 255:
            ipaddr[last_digit] += 1
            break
        else:
            ipaddr[last_digit] = 0
            if ipaddr[last_digit - 1] != 255:
                ipaddr[last_digit - 1] += 1
                break
    
    return join(ipaddr)


def assign_client_ip(lab):

    # Assigns an IP to the client in the given range for the lab.
    
    if get_next_ip_addr(allocation[lab][1]) == allocation[lab][2]:
        print "No more IP addresses are available"
        return None
    else:
        client_ip = allocation[lab][2]
        allocation[lab][2] = get_next_ip_addr(allocation[lab][2])
        return client_ip


def VLSM(network_addr, labs_info):

    """
    Variable length subnet masking method with args -
    labs_info is the list of the tuple of lab_name and number of hosts it can hold.
    network_addr is the address where we start off with.
    """

    need = 0
    allc =0
    bits = 0
    ipaddr = network_addr
    
    # Iterate over the labs' capacities
    for x in labs_info:

        bits = min_pow2(int(x[1]) + 2)
        ipaddr = get_network_address(ipaddr, convert_mask_to_ip(int(32 - bits)))

        #Get the first and last IPs
        first_addr = copy.deepcopy(ipaddr)  # list is mutable, not to change the global value
        first_addr[3] = int(int(first_addr[3]) + 1)

        last_addr = get_broadcast_address(ipaddr, convert_mask_to_ip(int(32 - bits)))
        last_addr[3] -= 1

        # Do the join of the first and last addresses here itself
        first_upd_addr = join (first_addr)
        last_upd_addr = join (last_addr)
        allocation.update({str(x[0]): [first_upd_addr]})
        allocation[x[0]].append(last_upd_addr)
        allocation[x[0]].append(first_upd_addr)

        #labs_dict[this_line[1]].append(str(this_line[0]))
        print "DEBUG: LAB SUBTNET MASKS "
        print "==========="
        print " SUBNET: %5s NEEDED: %3d (%3d %% of) ALLOCATED %4d ADDRESS: %15s :: %15s - %-15s :: %15s MASK: %d (%15s)" % \
              (x[0],
               int(x[1]),
               (int(x[1]) * 100) / (int(pow(2, bits)) - 2),
               int(pow(2, bits)) - 2,
               join(ipaddr),
               join(first_addr),
               join(last_addr),
               join(get_broadcast_address(ipaddr, convert_mask_to_ip(int(32 - bits)))),
               32 - bits,
               join(convert_mask_to_ip(int(32 - bits))))
        print "==========="

        need += int(x[1])
        allc += int(pow(2, bits)) - 2
        ipaddr = get_next_usable_addr(ipaddr, convert_mask_to_ip(int(32 - bits)))


def run_server():

    """
    Main DHCP server which allocates IPs to the hosts
    """
    dhcp_server = socket.socket()
    dhcp_server.bind((HOST, PORT))
    dhcp_server.listen(5)
    
    while True:
        conn, addr = dhcp_server.accept()
        print 'Got connection from', addr
        data = conn.recv(1024)
        print data

        if str(data) in mac_map:
            lab = str(mac_map[str(data)])
            new_client_ip = assign_client_ip(lab)
            if new_client_ip is None:
                new_client_ip = "IP Allocation Error: No IP available"
        else:
            lab = 'UNKNOWN'
            new_client_ip = assign_client_ip(lab)
            if new_client_ip is None:
                new_client_ip = "IP Allocation Error: No IP available"

        conn.send(new_client_ip)

        conn.close()


def main():

    # Check if file exists and open it
    try:
        subnet_file = open('subnets.conf', 'r')
    except OSError as err:
        print("OS Error: {0}".format(err))
        sys.exit(1)

    file_content = subnet_file.readlines()
    file_content = [x.strip() for x in file_content]

    # Validate the CIDR formatted: [IPv4]/[SubnetMask]
    validate_CIDR(file_content[0])

    # Store the validated CIDR in a variable for future use.
    CIDR = file_content[0]
    
    # Validate the type of "number of labs"
    try:
        num_of_labs = int(file_content[1])
    except TypeError as err:
        print("Type Error: {0}".format(err))
        sys.exit(1)
    
    # Get Capacity and MAC address objects for the labs
    capacity_of_labs = []
    labs = []
    mac_add = []
    labs_dict = {}

    for i in range(2, 2+num_of_labs):
        this_line = file_content[i].split(':')
        labs_dict.update({str(this_line[0]): [int(this_line[1])]})

    for i in range(2+num_of_labs, len(file_content)):
        this_line = file_content[i].split('-')
        mac_map.update({str(this_line[0]): str(this_line[1])})
        labs_dict[this_line[1]].append(str(this_line[0]))

    print "DEBUG: MAC ADDRESSES "
    print "========="
    print (mac_map)
    print "========="

    for key, value in labs_dict.items():
        labs.append(key)
        capacity_of_labs.append(value[0])
        for i in value[1:]:
            mac_add.append(str(i))

    # DOUBT: The number of hosts here are 10 but allocated is 14?!
    labs.append('UNKNOWN')
    capacity_of_labs.append(10)

    labs_info = zip(labs, capacity_of_labs)
    labs_info = sorted(labs_info, key=itemgetter(1), reverse=True)

    print "DEBUG: LABS INFO "
    print "========="
    print labs_info
    print "========="

    """
    VLSM SUBNET MASKING AND ASSIGNING IP ADDRESSES
    """

    #Split the subnet CIDR_format_string
    CIDR_format_string = CIDR.split('/')
    ip = CIDR_format_string[0]
    subnet_mask = CIDR_format_string[1]

    # We have to convert subnet masks to an equivalent IP format for processing. 
    subnet_list = convert_mask_to_ip(int(subnet_mask))

    # Calculate total capacity of the labs and if those satisfy the constraints
    total_hosts = check_lab_capacity(capacity_of_labs, subnet_mask)

    # Split ip into list
    ip_addr = ip.split(".")
    for x in xrange(len(ip_addr)):
        ip_addr[x] = int(ip_addr[x])

    # Send this ip to get the N.A.
    network_addr = get_network_address(ip_addr, subnet_list)

    # Run the variable length subnet masking function
    VLSM(network_addr, labs_info )

    """
    Run the main DHCP server
    """
    run_server()


if __name__ == '__main__':  # pragma: no cover
    sys.exit(main())
