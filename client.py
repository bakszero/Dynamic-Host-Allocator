import socket                   

#s = socket.socket()             
#host = ""


port = 1452
my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
my_socket.bind(('', 0))
my_socket.settimeout(2)
my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST,1)
my_socket.sendto("F8:D1:90:80:65:A8", ('<broadcast>' ,port))



#s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#s.bind(('', 0))
#s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
#server_address = ('<broadcast>', 45555)

#s.connect((host, port))
#s.send("F8:D1:90:80:65:A8")

while True:
    print('receiving data...')
    try:
        message , address = my_socket.recvfrom(1024)
        print 'message (%s) from : %s' % ( str(message), address[0])
    except:
        print "Write timeout on socket"
   
   
   
   
    #show_message('message from :'+ str(address[0]) , message)
    #data = my_socket.recv(1024)
    #print('data=%s', (data))
    

my_socket.close()
print('connection closed')