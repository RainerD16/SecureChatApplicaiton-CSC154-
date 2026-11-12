import socket
import json
import threading 

#set IP and PORT numbers first
HOST = "127.0.0.1"
PORT = 5000

username = input("Enter your username: ").strip() # Take a username from the user/client

def receiveMessages(serverFile):
    while True:
        try:
            incomingData = serverFile.readline()
            
            if not incomingData:
                break
            
            incomingMessage = json.loads(incomingData)
            
            # Take the recieved message and print info to the client
            if incomingMessage.get("type") == "message":
                sender = incomingMessage.get("from")
                text = incomingMessage.get("text")
                print(f"\n[{sender}]: {text}")
                
            elif incomingMessage.get("type") == "error":
                print(f"\nError: {incomingMessage.get('message')}")
                
        except (OSError, ValueError) as error:
            print(f"\nError receiving message: {error}")
            break

# A new socket object for the client is created
# Enable IPv4
# Set TCP for communication
clientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientSock.connect((HOST,PORT))



registration = {"type": "register", 
                "username": username} # Client registers a name, stored in a dicitonary for Server to process

outMessage = json.dumps(registration) + "\n"  #dictionary converted to JSON to be sent to server
clientSock.sendall(outMessage.encode("utf-8")) # Encode and send out to server

with clientSock.makefile("r", encoding="utf-8") as serverFile:
    incomingMessage = json.loads(serverFile.readline()) # obtain message from server

    if incomingMessage["type"] == "registered": 
        print(f"\nWelcome, {incomingMessage['username']}!")
        print(f"Users connected: {incomingMessage['online_users']}") 

        # sets up client server to continously listen for incoming messages from the server through threading
        receiveThread = threading.Thread(target=receiveMessages, args=(serverFile,), daemon=True)
        receiveThread.start()
        
        while True:
            recipient = input("\nEnter username of recipient (or 'exit' to quit): ").strip()
            if recipient.lower() == 'exit':
                print("Disconnecting...")
                clientSock.shutdown(socket.SHUT_RDWR)
                break   
            
            textInput = input("Enter your message: ")
            textOutput = {
                "type": "message",
                "to": recipient,
                "text": textInput
            }
            
            outputMessage = json.dumps(textOutput) + "\n"
            clientSock.sendall(outputMessage.encode("utf-8"))
        receiveThread.join() #wait for the receive thread to finish before closing the socket
    else:
        print(f"Registration failed: {incomingMessage['message']}")
        
clientSock.close()
print("Disconnected from server.")