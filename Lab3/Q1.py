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







# from Crypto.PublicKey import RSA
# import binascii

# # Function to generate RSA keys (n, e) and (n, d)
# def generate_rsa_keys():
#     key = RSA.generate(2048)
#     private_key = key
#     public_key = key.publickey()
#     return private_key, public_key

# # Function to encrypt a number using RSA public key (without padding)
# def encrypt_RSA_no_padding(public_key, number):
#     # Encrypt the message without padding, directly using modular exponentiation
#     return pow(number, public_key.e, public_key.n)

# # Function to decrypt a number using RSA private key (without padding)
# def decrypt_RSA_no_padding(private_key, ciphertext):
#     # Decrypt the ciphertext using modular exponentiation
#     return pow(ciphertext, private_key.d, private_key.n)

# # Function for homomorphic multiplication (RSA multiplicative property)
# def homomorphic_multiply(ciphertext1, ciphertext2, pub_key):
#     """Performs homomorphic multiplication on ciphertexts"""
#     return (ciphertext1 * ciphertext2) % pub_key.n

# # Generate RSA keys
# private_key, public_key = generate_rsa_keys()

# # Take two characters as input
# char1 = input("Enter the first character: ")
# char2 = input("Enter the second character: ")

# # Convert characters to their ASCII values
# ascii1 = ord(char1)
# ascii2 = ord(char2)

# # Encrypt the ASCII values (without padding)
# encrypted1 = encrypt_RSA_no_padding(public_key, ascii1)
# encrypted2 = encrypt_RSA_no_padding(public_key, ascii2)

# print(f"Encrypted ASCII value of '{char1}': {encrypted1}")
# print(f"Encrypted ASCII value of '{char2}': {encrypted2}")

# # Perform homomorphic multiplication (which reflects multiplication of plaintexts)
# encrypted_product = homomorphic_multiply(encrypted1, encrypted2, public_key)

# # Decrypt the product (which will reflect the multiplication of ASCII values)
# decrypted_product = decrypt_RSA_no_padding(private_key, encrypted_product)

# # Print the decrypted product
# print(f"Decrypted product of ASCII values: {decrypted_product}")
# print(f"Character: {chr(decrypted_product)}")
# print(f"Expected product of ASCII values: {ascii1 * ascii2}")








# from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_OAEP
# import binascii

# # Function to generate RSA keys (n, e) and (n, d)
# def generate_rsa_keys():
#     key = RSA.generate(2048)
#     private_key = key
#     public_key = key.publickey()
#     return private_key, public_key

# # Function to encrypt a number using RSA public key
# def encrypt_RSA(public_key, number):
#     cipher_rsa = PKCS1_OAEP.new(public_key)
#     encrypted_message = cipher_rsa.encrypt(number.to_bytes((number.bit_length() + 7) // 8, 'big'))
#     return int(binascii.hexlify(encrypted_message), 16)

# # Function to decrypt a number using RSA private key
# def decrypt_RSA(private_key, ciphertext):
#     cipher_rsa = PKCS1_OAEP.new(private_key)
#     ciphertext_bytes = binascii.unhexlify(hex(ciphertext)[2:])
#     decrypted_message = cipher_rsa.decrypt(ciphertext_bytes)
#     return int.from_bytes(decrypted_message, 'big')

