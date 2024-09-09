from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
import time
import binascii

message = "Performance Testing of Encryption Algorithms"
message_bytes = message.encode()
key_des = b"abcdefgh"
key_aes = b"0123456789ABCDEF0123456789ABCDEF"

def test_des_encryption_decryption(message_bytes, key, iterations=1000):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_message = pad(message_bytes, DES.block_size)

    start_time = time.time()
    for _ in range(iterations):
        ciphertext = cipher.encrypt(padded_message)
    encryption_time = (time.time() - start_time) / iterations

    cipher = DES.new(key, DES.MODE_ECB)
    start_time = time.time()
    for _ in range(iterations):
        decrypted_padded_message = cipher.decrypt(ciphertext)
        decrypted_message_bytes = unpad(decrypted_padded_message, DES.block_size)
    decryption_time = (time.time() - start_time) / iterations
    
    return encryption_time, decryption_time, decrypted_message_bytes

def test_aes_encryption_decryption(message_bytes, key, iterations=1000):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message_bytes, AES.block_size)

    start_time = time.time()
    for _ in range(iterations):
        ciphertext = cipher.encrypt(padded_message)
    encryption_time = (time.time() - start_time) / iterations

    cipher = AES.new(key, AES.MODE_ECB)
    start_time = time.time()
    for _ in range(iterations):
        decrypted_padded_message = cipher.decrypt(ciphertext)
        decrypted_message_bytes = unpad(decrypted_padded_message, AES.block_size)
    decryption_time = (time.time() - start_time) / iterations
    
    return encryption_time, decryption_time, decrypted_message_bytes

des_enc_time, des_dec_time, des_decrypted_message = test_des_encryption_decryption(message_bytes, key_des)
aes_enc_time, aes_dec_time, aes_decrypted_message = test_aes_encryption_decryption(message_bytes, key_aes)

print(f"DES Encryption Time (average over 1000 iterations): {des_enc_time:.6f} seconds")
print(f"DES Decryption Time (average over 1000 iterations): {des_dec_time:.6f} seconds")
print(f"AES-256 Encryption Time (average over 1000 iterations): {aes_enc_time:.6f} seconds")
print(f"AES-256 Decryption Time (average over 1000 iterations): {aes_dec_time:.6f} seconds")

print(f"DES Decrypted Message: {des_decrypted_message.decode()}")
print(f"AES-256 Decrypted Message: {aes_decrypted_message.decode()}")
