import socket
import json
import threading 
import base64
import time
import os
import binascii
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptographyUtil import generate_keypair, load_keypair, encryptAES, decryptAES, encryptRSA, decryptRSA, signMessage, verifyMessage, checkReplay

HOST = "127.0.0.1"
PORT = 5000

msgNum = 0 #tracks the message number; Like sequence number
lastMsgNum = {} #tracks the latest sequence number from each user
publicKeys = {} #store public keys from other users
username = input("Enter your username: ").strip() # Take a username from the user/client
password = input("Enter RSA key password: ")# Take a password from the user/client
keyReceived = threading.Event() #flags when another public key has been received

#Check if the user's RSA key pair already exists
if os.path.exists(f"{username}_private.pem") and os.path.exists(f"{username}_public.pem"):
    privateKey, publicKey = load_keypair(username, password)
else:
    privateKey, publicKey = generate_keypair(username, password)

#This converts the public key into PEM text for registration purposes
publicKeyPEM = publicKey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8")

def receiveMessages(serverFile):
    while True:
        try:
            incomingData = serverFile.readline()
            
            if not incomingData:
                break
            
            incomingMessage = json.loads(incomingData)
            
            if incomingMessage.get("type") == "message":
                sender = incomingMessage.get("from")

                # make sure the message is for current user
                if incomingMessage["to"] != username:
                    print("\nMessage error: Recipient invalid.")
                    continue

                #Validate sender public key existence
                if sender not in publicKeys:
                    print(f"\nMessage error: Public key for {sender} not found.")
                    continue

                #Decode the signature to verify the message
                signature = base64.b64decode(incomingMessage["signature"])
                if not verifyMessage(incomingMessage, signature, publicKeys[sender]):
                    print(f"\nMessage error: Signature verification failed.")
                    continue

                # Check if the message has already been received
                if not checkReplay(incomingMessage, lastMsgNum):
                    print(f"\nMessage error: Replay attack detected!!!")
                    continue

                # Decode the encrypted data
                encryptedKey = base64.b64decode(incomingMessage["encrypted_key"])
                nonce = base64.b64decode(incomingMessage["nonce"])
                ciphertext = base64.b64decode(incomingMessage["ciphertext"])

                # Decrypt the AES key using our private key, then decrypt the message
                aesKey = decryptRSA(encryptedKey, privateKey)
                text = decryptAES(aesKey, nonce, ciphertext)

                print(f"\n[{sender}]: {text}")
                lastMsgNum[sender] = incomingMessage["msgNum"]
                print("Signature has been verified.")
            
            elif incomingMessage.get("type") == "key_response":
                requestedUser = incomingMessage.get("username")
                publicKeyPEM = incomingMessage.get("public_key")      
                publicKeys[requestedUser] = serialization.load_pem_public_key(publicKeyPEM.encode("utf-8")) # Save received public key in client's dictionary
                print(f"\nPublic key received for {requestedUser}.")
                keyReceived.set()
                
            elif incomingMessage.get("type") == "error":
                print(f"\nError: {incomingMessage.get('message')}")
                
        except (ValueError, KeyError, TypeError, InvalidTag, binascii.Error) as error:
            print(f"\nMessage rejected: Invalid encrypted message. {error}")
            continue

        except OSError as error:
            print(f"\nConnection error: {error}")
            break


clientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientSock.connect((HOST,PORT))

# Registers the client username and public key to the server
registration = {
    "type": "register",
    "username": username,
    "public_key": publicKeyPEM
}

outMessage = json.dumps(registration) + "\n"  #dictionary converted to JSON to be sent to server
clientSock.sendall(outMessage.encode("utf-8")) # Encode and send out to server

with clientSock.makefile("r", encoding="utf-8") as serverFile:
    incomingMessage = json.loads(serverFile.readline()) # obtain message from server

    if incomingMessage["type"] == "registered": 
        print(f"\n*** Welcome, {incomingMessage['username']}! ***")
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

            if recipient.startswith("key "): # Request user's public key from server
                requestedUser = recipient[4:].strip()

                keyRequest = {
                    "type": "key_request",
                    "username": requestedUser
                }

                outputMessage = json.dumps(keyRequest) + "\n"
                clientSock.sendall(outputMessage.encode("utf-8"))
                continue

            if recipient not in publicKeys: # first check for the recipient's public key exists
                keyReceived.clear()
                keyRequest = {
                    "type": "key_request",
                    "username": recipient
                }

                outputMessage = json.dumps(keyRequest) + "\n"
                clientSock.sendall(outputMessage.encode("utf-8"))

                # Wait for server to send back the public key
                keyReceived.wait(timeout=5)

                if recipient not in publicKeys:
                    print(f"Public key for {recipient} not found.")
                    continue

            textInput = input("Enter your message: ")

            # Encrypt the message using AES, then encrypt the AES key using recipient's RSA public key
            aesKey, nonce, ciphertext = encryptAES(textInput)
            encryptedKey = encryptRSA(aesKey, publicKeys[recipient])

            msgNum += 1

            # Create the encrypted message dictionary
            textOutput = {
                "type": "message",
                "from": username,
                "to": recipient,
                "msgNum": msgNum,
                "timestamp": int(time.time()),
                "encrypted_key": base64.b64encode(encryptedKey).decode("utf-8"),
                "nonce": base64.b64encode(nonce).decode("utf-8"),
                "ciphertext": base64.b64encode(ciphertext).decode("utf-8")
            }

            # Sign the encrypted message using our RSA private key
            signature = signMessage(textOutput, privateKey)
            textOutput["signature"] = base64.b64encode(signature).decode("utf-8")

            # Send encrypted message to server
            outputMessage = json.dumps(textOutput) + "\n"
            clientSock.sendall(outputMessage.encode("utf-8"))

            print(f"Encrypted message #{msgNum} sent to {recipient}.")

        receiveThread.join() #wait for the receive thread to finish before closing the socket
    else:
        print(f"Registration failed: {incomingMessage['message']}")
        
clientSock.close()
print("Disconnected from server.")