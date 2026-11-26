import socket
import threading
import json
import sys
import base64

HOST = "127.0.0.1"
PORT = 5000

#code to enable malicous mode, allows server to choose different attacks
maliciousMode = len(sys.argv) > 1 and sys.argv[1] == "mal"
attack = "" 

if maliciousMode:
    print("Malicious server mode enabled.")
    print("1. Modify ciphertext")
    print("2. Modify message number")
    print("3. Redirect message to Carol")
    print("4. Replay message")

    attack = input("Select an attack: ")

clients = {} #stores currently connected clients
publicKeys = {} #stores public keys

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
        publicKey = registration.get("public_key")#sets public key from the client
        
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
                publicKeys[username] = publicKey
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

            # Check if a client is requesting another user's public key for sending encrypted messages
            if msg.get("type") == "key_request":
                requestedUser = msg.get("username")

                with clientsLock:
                    requestedKey = publicKeys.get(requestedUser)

                if requestedKey is None:
                    sendJSON(clientSock, {
                        "type": "error",
                        "message": f"Public key for {requestedUser} not found."
                    })
                else:
                    sendJSON(clientSock, {
                        "type": "key_response",
                        "username": requestedUser,
                        "public_key": requestedKey
                    })

                print(f"{username} requested public key for {requestedUser}")
                continue
           
            # Forward encrypted messages to recipient
            if msg.get("type") == "message":
                recipient = msg.get("to")

                if msg.get("from") != username: # Verify the message came from the registered sender
                    sendJSON(clientSock, {
                        "type": "error",
                        "message": "Invalid sender."
                    })
                    continue
                
                 # This is attack 3 which sends a message meant for Bob to Carol instead      
                if maliciousMode and attack == "3" and recipient == "Bob":
                    recipient = "Carol"
                    print("Bob's next incoming message was redirected to Carol.")
                    
                with clientsLock:
                    recipientSock = clients.get(recipient)

                if recipientSock is None:
                    sendJSON(clientSock, {
                        "type": "error",
                        "message": f"User '{recipient}' not found or is offline."
                    })
                    continue
                
                #If attack 1 was picked in malicious mode, flip a single byte of the ciphertext
                if maliciousMode and attack == "1":
                    ciphertext = bytearray(base64.b64decode(msg["ciphertext"]))
                    ciphertext[0] ^= 1
                    msg["ciphertext"] = base64.b64encode(ciphertext).decode("utf-8")
                    print("Ciphertext has been modified.")

                # this is Attack 2 which modifies the message sequence number
                if maliciousMode and attack == "2":
                    msg["msgNum"] += 1
                    print("Message sequence number has been modified.")
                    
                sendJSON(recipientSock, msg) # send the encrypted message
                print(f"Encrypted message #{msg['msgNum']} forwarded from {username} to {recipient}")
                print(f"Ciphertext: {msg['ciphertext']}")
                
                # Attack 4 sends the same message again (replay attack)
                if maliciousMode and attack == "4":
                    sendJSON(recipientSock, msg)
                    print("Previous message replayed.")
            else:
                sendJSON(clientSock, {
                    "type": "error",
                    "message": "Unknown message type."
                })
                   
    except (OSError, ValueError) as error:
        print(f"Client error: {error}")
        
    finally:
        # Remove user and their key when they disconnect
        if username:
            with clientsLock:
                if clients.get(username) is clientSock:
                    del clients[username]
                    del publicKeys[username]
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