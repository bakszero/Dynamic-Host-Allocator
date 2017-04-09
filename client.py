import socket                   

s = socket.socket()             
host = ""
port = 1443

s.connect((host, port))
s.send("Hello server!")

while True:
    print('receiving data...')
    data = s.recv(1024)
    print('data=%s', (data))
    if not data:
        break

s.close()
print('connection closed')