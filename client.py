import socket
import json

#set IP and PORT numbers first
HOST = "127.0.0.1"
PORT = 5000

username = input("Enter your username: ").strip() # Take a username from the user/client

# A new socket object for the client is created
# Enable IPv4
# Set TCP for communication
clientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientSock.connect((HOST,PORT))



registration = {"type": "register", "username": username} # Client registers a name, stored in a dicitonary for Server to process

outMessage = json.dumps(registration) + "\n"  #dictionary converted to JSON to be sent to server
clientSock.sendall(outMessage.encode("utf-8")) # Encode and send out to server

with clientSock.makefile("r", encoding="utf-8") as serverFile:
    incomingMessage = json.loads(serverFile.readline()) # obtain message from server

    if incomingMessage["type"] == "registered": 
        print(f"\nWelcome, {incomingMessage['username']}!")
        print(f"Users connected: {incomingMessage['online_users']}") 

        # Keep client connected
        input("\nPress Enter to disconnect...")
    else:
        print(f"Registration failed: {incomingMessage['message']}")

clientSock.close()
print("Disconnected from server.")