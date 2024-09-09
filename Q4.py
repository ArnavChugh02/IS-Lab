from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import binascii

# Define the key and message
key = binascii.unhexlify("1234567890ABCDEF1234567890ABCDEF")  # 24-byte key for Triple DES
message = "Classified Text"

# Convert the message to bytes
message_bytes = message.encode()

# Create a DES3 cipher object with the given key
cipher = DES3.new(key, DES3.MODE_ECB)

# Pad the message to be a multiple of block size (8 bytes for DES3)
padded_message = pad(message_bytes, DES3.block_size)

# Encrypt the message
ciphertext = cipher.encrypt(padded_message)

# Decrypt the message
cipher = DES3.new(key, DES3.MODE_ECB)
decrypted_padded_message = cipher.decrypt(ciphertext)

# Remove padding
decrypted_message_bytes = unpad(decrypted_padded_message, DES3.block_size)
decrypted_message = decrypted_message_bytes.decode()

# Print results
print(f"Original message: {message}")
print(f"Ciphertext (hex): {binascii.hexlify(ciphertext).decode()}")
print(f"Decrypted message: {decrypted_message}")
