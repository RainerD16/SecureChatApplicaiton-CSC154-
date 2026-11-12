import socket
import threading
import json

#Setting the host ip and port first
HOST = "127.0.0.1"
PORT = 5000

clients = {} #dictionary to hold new client names

clientsLock = threading.Lock()

# This converts plain text message into json format and sends it out
def sendJSON(clientSock, msg):
    data = json.dumps(msg) + "\n"
    clientSock.sendall(data.encode("utf-8"))
    
# This function is used to handle new client connections. It will receive, print and acknowledge new client messages, and also close the client socket if a disconnect is detected
def clientConnection(clientSock, clientAddress):
    print(f"New connection received from client: {clientAddress}")

    username = None
    clientFile = None
    try:
        # Reads the registration message from the clent
        clientFile = clientSock.makefile("r", encoding="utf-8")
        incomingData = clientFile.readline()

        if not incomingData: 
            return

        registration = json.loads(incomingData)

        # Error checking if client has registered or not
        if registration.get("type") != "register":
            sendJSON(clientSock, {
                "type": "error",
                "message": "Registration required."
            })
            return

        username = registration.get("username", "").strip() #sets username from the client

        if username == "": #error echecking if username is filled or not
            sendJSON(clientSock, {
                "type": "error",
                "message": "Username cannot be empty."
            })
            return

        with clientsLock: # Check if username is already taken
            if username in clients:
                registered = False
            else:
                clients[username] = clientSock
                registered = True
                onlineUsers = list(clients.keys())

        if registered == False:
            sendJSON(clientSock, {
                "type": "error",
                "message": "Username already taken."
            })
            return

        #confirm user registration and list online users
        print(f"{username} registered successfully.")
        print(f"Online users: {onlineUsers}\n")

        # Send registration confirmation
        sendJSON(clientSock, {"type": "registered", 
                              "username": username, 
                              "online_users": onlineUsers})
        
        # Keep connection open until client disconnects
        while True:
            incomingData = clientFile.readline()
            if not incomingData:
                break
            
            msg = json.loads(incomingData)
            
            #checks the type of message received from the client. If it is a message, it will extract the recipient and text from the message
            if msg.get("type") == "message":
                recipient = msg.get("to")
                text = msg.get("text")
                
                #input validation
                if not isinstance(recipient, str) or not isinstance(text, str):
                    sendJSON(clientSock, {
                        "type": "error",
                        "message": "Invalid message format."
                    })
                    continue
                
                with clientsLock:
                    recipientSock = clients.get(recipient)
                
                #error checking if the recipient is online or not, sending a message that the user is unavailable
                if recipientSock is None:
                    sendJSON(clientSock, {
                        "type": "error",
                        "message": f"User '{recipient}' not found or is offline."
                    })
                    continue
                
                fullMessage = {
                    "type": "message",
                    "from": username,
                    "text": text
                }
                
                sendJSON(recipientSock, fullMessage)
                print(f"Message sent from {username} to {recipient}")
                
            else:
                sendJSON(clientSock, {
                    "type": "error",
                    "message": "Unknown message type."
                })
                   
    except (OSError, ValueError) as error:
        print(f"Client error: {error}")
        
    finally:
        # Remove user when they disconnect
        if username:
            with clientsLock:
                if clients.get(username) is clientSock:
                    del clients[username]
        if clientFile is not None:
            clientFile.close()
        
        clientSock.close()
        print(f"Client {clientAddress} disconnected.\n")
    
serverSock= socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
serverSock.bind((HOST, PORT)) # Gives the server a host IP and a port to listen to. In this case, port 5000
serverSock.listen() # This makes the server listen on port 5000, opening communication 
print(f"Server listening on PORT:{PORT} for connection...\n")

while True:
    # Server will wait until a connectin is recieved. Server.accept() returns new socket object and client IP address and port number.
    clientSock, clientAddress = serverSock.accept()
    
    # This creates a new thread per new client, allowing messages to be sent to server all at once. 
    clientThread = threading.Thread( target = clientConnection, args=(clientSock, clientAddress))
    
    clientThread.start()