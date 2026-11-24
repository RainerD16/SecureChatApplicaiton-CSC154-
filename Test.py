
import base64
import time
from cryptographyUtil import generate_keypair, encryptAES, decryptAES, encryptRSA, decryptRSA, signMessage, verifyMessage, checkReplay

# Generate test RSA keys for Alice and Bob
alicePrivateKey, alicePublicKey = generate_keypair("TestAlice", "test123")
bobPrivateKey, bobPublicKey = generate_keypair("TestBob", "test123")

lastMsgNum = {}

# Alice enters a message for Bob
message = input("Enter message to Bob: ")

# Encrypt the message using AES, then encrypt the AES key using Bob's public key
aesKey, nonce, ciphertext = encryptAES(message)
encryptedKey = encryptRSA(aesKey, bobPublicKey)

# Create the message information
msg = {
    "from": "Alice",
    "to": "Bob",
    "msgNum": 1,
    "timestamp": int(time.time()),
    "encrypted_key": base64.b64encode(encryptedKey).decode("utf-8"),
    "nonce": base64.b64encode(nonce).decode("utf-8"),
    "ciphertext": base64.b64encode(ciphertext).decode("utf-8")
}

# Alice signs the message using her private key
signature = signMessage(msg, alicePrivateKey)

print("\nMessage encrypted and signed successfully.")

# Bob checks if the message number is new
if checkReplay(msg, lastMsgNum):

    # Verify the message signature before decrypting
    if verifyMessage(msg, signature, alicePublicKey):
        print("Signature valid.")

        # Decode the encrypted data from base64
        receivedKey = base64.b64decode(msg["encrypted_key"])
        receivedNonce = base64.b64decode(msg["nonce"])
        receivedCiphertext = base64.b64decode(msg["ciphertext"])

        # Bob decrypts the AES key and then the message
        recoveredKey = decryptRSA(receivedKey, bobPrivateKey)
        decryptedMessage = decryptAES(recoveredKey, receivedNonce, receivedCiphertext)

        print(f"Bob received: {decryptedMessage}")

        # Update the highest accepted message number
        lastMsgNum[msg["from"]] = msg["msgNum"]

    else:
        print("Invalid signature. Message rejected.")
else:
    print("Replay detected. Message rejected.")

# Test 1: Change the recipient after Alice signs the message
print("\nTest 1: Modify message recipient")
modifiedMsg = msg.copy()
modifiedMsg["to"] = "Carol"

if verifyMessage(modifiedMsg, signature, alicePublicKey):
    print("Signature valid.")
else:
    print("Invalid signature. Message rejected.")

# Test 2: Change the ciphertext after Alice signs the message
print("\nTest 2: Modify ciphertext")
modifiedMsg = msg.copy()
modifiedMsg["ciphertext"] = "modifiedCiphertext"

if verifyMessage(modifiedMsg, signature, alicePublicKey):
    print("Signature valid.")
else:
    print("Invalid signature. Message rejected.")

# Test 3: Replay the original message
print("\nTest 3: Replay original message")

if checkReplay(msg, lastMsgNum):
    print("Message accepted.")
else:
    print("Replay detected. Message rejected.")
