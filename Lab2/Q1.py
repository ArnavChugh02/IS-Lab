from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import binascii

# DES requires an 8-byte key and an 8-byte block size
key = b'A1B2C3D4'
data = b'Confidential Data'

# Pad the data to ensure it is a multiple of 8 bytes
padded_data = pad(data, DES.block_size)

# Encrypt the data
cipher = DES.new(key, DES.MODE_ECB)
ciphertext = cipher.encrypt(padded_data)

# Print ciphertext in hexadecimal format
print("Ciphertext (hex):", binascii.hexlify(ciphertext))

# Decrypt the ciphertext
decrypted_padded_data = cipher.decrypt(ciphertext)

# Unpad the decrypted data to get the original message
decrypted_data = unpad(decrypted_padded_data, DES.block_size)

# Print the decrypted data
print("Decrypted data:", decrypted_data.decode('utf-8'))
