import socket
#set IP and PORT numbers first
HOST = "127.0.0.1"
PORT = 5000

# A new socket object for the client is created
# Enable IPv4
# Set TCP for communication
clientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientSock.connect((HOST,PORT))

outMessage = input("Type your message: ") # Take a message from the user/client
clientSock.sendall(outMessage.encode("utf-8")) # Encode message and send out to server

# Take any incoming data from the server and decode, then print the message
recievedData = clientSock.recv(1024) 
serverResponse = recievedData.decode("utf-8")
print(f"Message from server: {serverResponse}")

clientSock.close() #close the connection