import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
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

    
