
from cryptographyUtil import generate_keypair, encryptAES, decryptAES, encryptRSA, decryptRSA

bobPrivateKey, bobPublicKey = generate_keypair("Bob", "awdfeafwafe")
message = input("Enter message to Bob: ")
aesKey, nonce, ciphertext = encryptAES(message)

encryptedKey = encryptRSA(aesKey, bobPublicKey)
print("\nMessage encrypted successfully.")

print(f"Encrypted message: {ciphertext.hex()}")
print(f"Encrypted AES key: {encryptedKey.hex()}")

recoveredKey = decryptRSA(encryptedKey, bobPrivateKey)
decryptedMessage = decryptAES(recoveredKey, nonce, ciphertext)

print(f"\nBob received: {decryptedMessage}")
print(f"Message validity: {message == decryptedMessage}")
