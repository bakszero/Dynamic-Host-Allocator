import sys
import os
import re
import math
from operator import itemgetter


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
    print (total_capacity)

    #check if lab capacity is valid. If not, raise an error.
    if total_capacity > (pow(2, 32 - int(subnet_mask)) - 2):
        exit("ERROR: Too many hosts")
    else:
        return total_capacity


def get_network_address(,subnet_mask):
    for x in xrange(4):
        NA = [0]
    for x in xrange(4):
        NA[x] = int(ipaddr[i]) & int(nmask[i])  # octet and subnetmask
    return net
    
def main():

    # Check if file exists and open it
    try:
        subnet_file = open('subnets.conf', 'r')
    except OSError as err:
        print("OS Error: {0}".format(err))
        sys.exit(1)

    file_content = subnet_file.readlines()
    #print file_content
    file_content = [x.strip() for x in file_content]
    #print (file_content)

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

    #print (labs_dict)

    for i in range(2+num_of_labs, 2+num_of_labs*3):
        this_line = file_content[i].split('-')
        labs_dict[this_line[1]].append(str(this_line[0]))

    print (labs_dict)

    for key, value in labs_dict.items():
        labs.append(key)
        capacity_of_labs.append(value[0])
        #We may have multiple MAc addresses, so adding that to the mac_address list
        for i in value[1:]:
            mac_add.append(str(i))

    print (capacity_of_labs)

    #No need to add mac address to labs(as of now atleast!)
    labs_info = zip(labs, capacity_of_labs)

    #print (labs_info)

    # Sort labs according to number of hosts - ('Lab_name', number_of_hosts, 'MAC addr')
    #Added reverse = True
    #Removed mac_address as it is not entirely necessary at the moment
    labs_info = sorted(labs_info, key=itemgetter(1), reverse=True)

    # Print them one by one
    for eachLab in labs_info:
        print eachLab



    #VLSM SUBNET MASKING AND ASSIGNING IP ADDRESSES 

    #Split the subnet CIDR_format_string
    CIDR_format_string = CIDR.split('/')
    ip = CIDR_format_string[0]
    subnet_mask = CIDR_format_string[1]
    #print (subnet_mask)

    #WE have to convert subnet masks to an equivalent IP format for processing. 

    subnet_list = convert_mask_to_ip(int(subnet_mask))
    #print subnet_list

    #Calculate total capacity of the labs and if those satisfy the constraints
    total_hosts = check_lab_capacity(capacity_of_labs, subnet_mask)
    

    #Get the Network Address from the given IP address and subnet mask














if __name__ == '__main__':  # pragma: no cover
    sys.exit(main())
