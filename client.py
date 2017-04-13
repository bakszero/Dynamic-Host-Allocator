import socket                   

#s = socket.socket()             
#host = ""
port = 1452
my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST,1)
my_socket.sendto("F8:D1:90:80:65:A8", ('<broadcast>' ,port))
#s.connect((host, port))
#s.send("F8:D1:90:80:65:A8")

while True:
    print('receiving data...')
    data = my_socket.recv(1024)
    print('data=%s', (data))
    if not data:
        break

my_socket.close()
print('connection closed')