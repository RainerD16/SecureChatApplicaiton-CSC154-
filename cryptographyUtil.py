import os
import hashlib
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Generates a new RSA key pair and saves both keys in PEM format
def generate_keypair(username, password):
    privateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    publicKey = privateKey.public_key()

    with open(f"{username}_private.pem", "wb") as file:     # Save private key protected by user's password
        file.write(privateKey.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8"))))

    with open(f"{username}_public.pem", "wb") as file:     # Save public key
        file.write(publicKey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))

    print(f"RSA keys generated for {username}")
    return privateKey, publicKey

#Loads an RSA key pair from the user's existing PEM files
def load_keypair(username, password):

    with open(f"{username}_private.pem", "rb") as file:    # Read the user's private key
        privateKey = serialization.load_pem_private_key(file.read(), password=password.encode("utf-8"))

    with open(f"{username}_public.pem", "rb") as file: # Read the user's public key
        publicKey = serialization.load_pem_public_key(file.read())

    print(f"RSA keys loaded for {username}")
    return privateKey, publicKey

# Encrypts a message using a new AES-256 key and temporary random number; returns the AES key, nonce, and ciphertext
def encryptAES(message):
    
    aesKey = AESGCM.generate_key(bit_length=256) # Generate a new 256-bit AES key 
    nonce = os.urandom(12)  # Generate a random 12 byte nonce (random number one time use)

    data = message.encode("utf-8") # Convert the message into bytes before encrypting
    ciphertext = AESGCM(aesKey).encrypt(nonce, data, None) # message encryption 

    return aesKey, nonce, ciphertext

#Decrypts an AES encrypted message using its key and nonce; returns the original message
def decryptAES(aesKey, nonce, ciphertext):
    data = AESGCM(aesKey).decrypt(nonce, ciphertext, None)
    return data.decode("utf-8") # return decrypted bytes back into readable text


# Encrypts the AES key using the receiver's RSA public key; returns the encrypted AES key
def encryptRSA(aesKey, receiverPublicKey):
     return receiverPublicKey.encrypt(aesKey, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                                                #padding.OAEP specifies RSA-OAEP padding

# Decrypts the encrypted AES key using the receiver's private key; returns original AES key
def decryptRSA(encryptedKey, receiverPrivateKey):
   return receiverPrivateKey.decrypt(encryptedKey, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

# Hashes the message information using SHA-256
def hashMessage(msg):
    # Combine the sender, recipient, message number, timestamp and encrypted data into a single string
    fields = [
        msg["from"],
        msg["to"],
        str(msg["msgNum"]), 
        str(msg["timestamp"]), #message number and timestamp used to keep order and prevent replay attacks
        msg["encrypted_key"],
        msg["nonce"],
        msg["ciphertext"]
    ]
    # The string of fields is then encoded and hashed producing uniqueness and integrity of the message
    data = "|".join(fields).encode("utf-8")
    return hashlib.sha256(data).digest()

# Signs the message hash using the sender's RSA private key
def signMessage(msg, senderPrivateKey):
    digest = hashMessage(msg) #hashing using previously defined hashMessage function
    #return the signed hash with sender private key
    return senderPrivateKey.sign(digest, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), utils.Prehashed(hashes.SHA256()))
    
    
# verify the message signature using the sender's RSA public key
def verifyMessage(msg, signature, senderPublicKey):
    #hash message first as an integrity check to ensure the message has not been tampered with
    digest = hashMessage(msg) 
    try:
        senderPublicKey.verify(signature, digest, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), utils.Prehashed(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

# Check if the message number has already been received from the sender. If it has, this signifies an error or a replay attack.
# use this flag later to reject a message or send alert
def checkReplay(msg, lastMsgNum):
    sender = msg["from"]
    msgNum = msg["msgNum"]
    
    if sender in lastMsgNum: #checks if the sender is already in the lastMsgNum dictionary, and if the message number has been repeated
        if msgNum <= lastMsgNum[sender]:
            return False
    return True
