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
