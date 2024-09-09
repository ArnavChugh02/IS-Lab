import time
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_rsa_keypair(bits=2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public_key = private_key.public_key()
    return private_key, public_key

def generate_ecc_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_file_rsa(public_key, file_path, output_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(output_path, 'wb') as f:
        f.write(ciphertext)

def decrypt_file_rsa(private_key, file_path, output_path):
    with open(file_path, 'rb') as f:
        ciphertext = f.read()
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(output_path, 'wb') as f:
        f.write(plaintext)

def encrypt_file_ecc(public_key, file_path, output_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    encryption_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )[:32]
    cipher = Cipher(algorithms.AES(encryption_key), modes.ECB())
    encryptor = cipher.encryptor()
    pad_len = 16 - (len(data) % 16)
    padded_data = data + bytes([pad_len] * pad_len)
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    with open(output_path, 'wb') as f:
        f.write(ciphertext)

def decrypt_file_ecc(private_key, file_path, output_path):
    with open(file_path, 'rb') as f:
        ciphertext = f.read()
    encryption_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )[:32]
    cipher = Cipher(algorithms.AES(encryption_key), modes.ECB())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = plaintext[-1]
    plaintext = plaintext[:-pad_len]
    with open(output_path, 'wb') as f:
        f.write(plaintext)

def measure_performance():
    start_time = time.time()
    rsa_private_key, rsa_public_key = generate_rsa_keypair()
    rsa_keygen_time = time.time() - start_time

    start_time = time.time()
    ecc_private_key, ecc_public_key = generate_ecc_keypair()
    ecc_keygen_time = time.time() - start_time

    file_size = 1024 * 1024
    test_file_path = 'test_file.txt'
    encrypted_file_path_rsa = 'encrypted_rsa.bin'
    decrypted_file_path_rsa = 'decrypted_rsa.txt'
    encrypted_file_path_ecc = 'encrypted_ecc.bin'
    decrypted_file_path_ecc = 'decrypted_ecc.txt'

    with open(test_file_path, 'wb') as f:
        f.write(os.urandom(file_size))

    start_time = time.time()
    encrypt_file_rsa(rsa_public_key, test_file_path, encrypted_file_path_rsa)
    rsa_encryption_time = time.time() - start_time

    start_time = time.time()
    decrypt_file_rsa(rsa_private_key, encrypted_file_path_rsa, decrypted_file_path_rsa)
    rsa_decryption_time = time.time() - start_time

    start_time = time.time()
    encrypt_file_ecc(ecc_public_key, test_file_path, encrypted_file_path_ecc)
    ecc_encryption_time = time.time() - start_time

    start_time = time.time()
    decrypt_file_ecc(ecc_private_key, encrypted_file_path_ecc, decrypted_file_path_ecc)
    ecc_decryption_time = time.time() - start_time

    print("RSA Key Generation Time: {:.2f} seconds".format(rsa_keygen_time))
    print("ECC Key Generation Time: {:.2f} seconds".format(ecc_keygen_time))
    print("RSA Encryption Time: {:.2f} seconds".format(rsa_encryption_time))
    print("RSA Decryption Time: {:.2f} seconds".format(rsa_decryption_time))
    print("ECC Encryption Time: {:.2f} seconds".format(ecc_encryption_time))
    print("ECC Decryption Time: {:.2f} seconds".format(ecc_decryption_time))

if __name__ == '__main__':
    measure_performance()
