from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii

key = binascii.unhexlify("0123456789ABCDEF0123456789ABCDEF")
message = "Sensitive Information"

message_bytes = message.encode()
cipher = AES.new(key, AES.MODE_ECB)

padded_message = pad(message_bytes, AES.block_size)
ciphertext = cipher.encrypt(padded_message)
cipher = AES.new(key, AES.MODE_ECB)

decrypted_padded_message = cipher.decrypt(ciphertext)
decrypted_message_bytes = unpad(decrypted_padded_message, AES.block_size)
decrypted_message = decrypted_message_bytes.decode()

print(f"Original message: {message}")
print(f"Ciphertext (hex): {binascii.hexlify(ciphertext).decode()}")
print(f"Decrypted message: {decrypted_message}")
