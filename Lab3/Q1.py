from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import binascii

key = RSA.generate(2048)
public_key = key.publickey()
private_key = key

message = "Asymmetric Encryption"
message_bytes = message.encode()

cipher_rsa = PKCS1_OAEP.new(public_key)
ciphertext = cipher_rsa.encrypt(message_bytes)

cipher_rsa = PKCS1_OAEP.new(private_key)
decrypted_message_bytes = cipher_rsa.decrypt(ciphertext)
decrypted_message = decrypted_message_bytes.decode()

print(f"Original message: {message}")
print(f"Ciphertext (hex): {binascii.hexlify(ciphertext).decode()}")
print(f"Decrypted message: {decrypted_message}")


# from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_OAEP
# import binascii

# # Function to generate RSA keys (n, e) and (n, d)
# def generate_rsa_keys():
#     key = RSA.generate(2048)
#     private_key = key
#     public_key = key.publickey()
#     return private_key, public_key

# # Function to encrypt a message using RSA public key
# def encrypt_RSA(public_key, message):
#     cipher_rsa = PKCS1_OAEP.new(public_key)
#     # If the message is an integer, convert it to string first
#     if isinstance(message, int):
#         message = str(message)
#     encrypted_message = cipher_rsa.encrypt(message.encode('utf-8'))
#     return binascii.hexlify(encrypted_message).decode('utf-8')

# # Function to decrypt a message using RSA private key
# def decrypt_RSA(private_key, ciphertext):
#     cipher_rsa = PKCS1_OAEP.new(private_key)
#     encrypted_bytes = binascii.unhexlify(ciphertext.encode('utf-8'))
#     decrypted_message = cipher_rsa.decrypt(encrypted_bytes)
#     return decrypted_message.decode('utf-8')

# # Generate RSA keys
# private_key, public_key = generate_rsa_keys()

# # Example input: you can use an integer or a string
# numchar = 12345  # This is an integer
# # numchar = "Asymmetric Encryption"  # This is a string

# # Encrypt the message with the public key
# ciphertext = encrypt_RSA(public_key, numchar)
# print(f"Encrypted: {ciphertext}")

# # Decrypt the ciphertext with the private key
# decrypted_message = decrypt_RSA(private_key, ciphertext)
# print(f"Decrypted: {decrypted_message}")
