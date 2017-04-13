import socket                   
import sys
from uuid import getnode as get_mac


#MAC ADDRESS
mac = get_mac()
mac_default =':'.join(("%012X" % mac)[i:i+2] for i in range(0, 12, 2))


if (len(sys.argv) >1):
    if (sys.argv[1] == "-m"):
        mac = str(sys.argv[2])
    else:
        mac = mac_default
#else:
  #  print "Please specify command line args as ./client.py -m \"MAC_addr\""
  #  sys.exit(1)
        

#print mac




port = 1452
my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
my_socket.bind(('', 0))
my_socket.settimeout(100)
my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST,1)
my_socket.sendto("F8:D0:90:9D:68:16", ('<broadcast>' ,port))



#s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#s.bind(('', 0))
#s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
#server_address = ('<broadcast>', 45555)

#s.connect((host, port))
#s.send("F8:D1:90:80:65:A8")

while True:
    #print('receiving data...')
    try:
        message , address = my_socket.recvfrom(1024)
        #print 'message (%s) from : %s' % ( str(message), address[0])
        print (message)
    except socket.timeout:
        #print "Write timeout on socket"
        sys.exit()
   
   
   
   
    #show_message('message from :'+ str(address[0]) , message)
    #data = my_socket.recv(1024)
    #print('data=%s', (data))
    

my_socket.close()
print('connection closed')