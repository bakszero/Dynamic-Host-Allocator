import socket                   

s = socket.socket()             
host = ""
port = 1445

s.connect((host, port))
s.send("F8:D1:90:80:65:A8")

while True:
    print('receiving data...')
    data = s.recv(1024)
    print('data=%s', (data))
    if not data:
        break

s.close()
print('connection closed')