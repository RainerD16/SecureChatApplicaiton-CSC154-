import socket
#Setting the host ip and port first
HOST = "127.0.0.1"
PORT = 5000

# A new socket object named 'server' is created
# IPv4 addresses enabled, Example IP formats: 127.0.0.0, 192.0.0.0 ...
# Specify TCP for communication
serverSock= socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
serverSock.bind((HOST, PORT)) # Gives the server a host IP and a port to listen to. In this case, port 5000
serverSock.listen() # This makes the server listen on port 5000, opening communication 
print(f"Server listening on PORT:{PORT}...\n")

# Server will wait until a connectin is recieved. Server.accept() returns new socket object and client IP address and port number.
clientSock, clientAddress = serverSock.accept()
print(f"Connection recieved from client: {clientAddress}")

#This part decodes the data from the client, prints the message received, and sends an acknowledgment message to the client.
data = clientSock.recv(1024)
msg = data.decode("utf-8")
print(f"Message from {clientAddress}: {msg}")
clientSock.sendall("Recieved your message.".encode("utf-8"))

#close connections
clientSock.close()
serverSock.close()