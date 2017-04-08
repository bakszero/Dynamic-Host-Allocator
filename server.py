import sys
import os
import re
from operator import itemgetter


def validate_CIDR(CIDR_format_string):

    valid_IP_regex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"

    CIDR_format_string = CIDR_format_string.split('/')
    ip = CIDR_format_string[0]
    subnet_mask = CIDR_format_string[1]

    if not re.match(valid_IP_regex, ip):
        print "Invalid IPv4 has been provided."

    try:
        subnet_mask = int(subnet_mask)
    except TypeError as err:
        print("Type Error: {0}".format(err))
        sys.exit(1)

    if not subnet_mask < 33:
        print "Invalid Subnet Mask has been provided."


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
    
    # Validate the type of "number of labs"
    try:
        num_of_labs = int(file_content[1])
    except TypeError as err:
        print("Type Error: {0}".format(err))
        sys.exit(1)
    
    # Get Capacity and MAC address objects for the labs
    capacity_of_labs = []
    labs = []
    MAC_of_labs = []

    for i in range(2, 2+num_of_labs):
        this_line = file_content[i].split(':')
        labs.append(str(this_line[0]))
        capacity_of_labs.append(int(this_line[1]))

    for i in range(2+num_of_labs, 2+num_of_labs*2):
        this_line = file_content[i].split('-')
        MAC_of_labs.append(str(this_line[0]))

    labs_info = zip(labs, capacity_of_labs, MAC_of_labs)

    # Sort labs according to number of hosts
    labs_info = sorted(labs_info, key=itemgetter(1))


if __name__ == '__main__':  # pragma: no cover
    sys.exit(main())
