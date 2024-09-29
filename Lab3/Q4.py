import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Generate and compare RSA and ECC keys


def generate_rsa_key():
    start = time.time()
    key = RSA.generate(2048)
    end = time.time()
    print(f"RSA Key Generation Time: {end - start:.5f} seconds")
    return key


def generate_ecc_key():
    start = time.time()
    key = ec.generate_private_key(ec.SECP256R1())
    end = time.time()
    print(f"ECC Key Generation Time: {end - start:.5f} seconds")
    return key

# Encrypt file with RSA


def rsa_encrypt_file(file_path, public_key):
    with open(file_path, "rb") as f:
        plaintext = f.read()

    cipher_rsa = PKCS1_OAEP.new(public_key)
    start = time.time()
    # RSA (2048-bit) can only encrypt a limited amount of data at once
    ciphertext = cipher_rsa.encrypt(plaintext[:190])
    end = time.time()
    print(f"RSA Encryption Time: {end - start:.5f} seconds")

    return ciphertext

# Decrypt file with RSA


def rsa_decrypt_file(ciphertext, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    start = time.time()
    decrypted_data = cipher_rsa.decrypt(ciphertext)
    end = time.time()
    print(f"RSA Decryption Time: {end - start:.5f} seconds")

    return decrypted_data

# Encrypt file with ECC (using AES symmetric encryption for the actual data)


def ecc_encrypt_file(file_path, public_key):
    # Shared key derivation
    private_key = ec.generate_private_key(ec.SECP256R1())
    shared_key = private_key.exchange(ec.ECDH(), public_key)

    # Derive symmetric key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'encryption'
    ).derive(shared_key)

    # Encrypt file with AES
    with open(file_path, "rb") as f:
        plaintext = f.read()

    iv = get_random_bytes(16)
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv))
    encryptor = cipher.encryptor()

    start = time.time()
    ciphertext = iv + encryptor.update(plaintext) + encryptor.finalize()
    end = time.time()
    print(f"ECC Encryption Time: {end - start:.5f} seconds")

    return ciphertext, private_key

# Decrypt file with ECC


def ecc_decrypt_file(ciphertext, private_key, peer_public_key):
    # Shared key derivation
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

    # Derive symmetric key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'encryption'
    ).derive(shared_key)

    # Decrypt file with AES
    iv = ciphertext[:16]
    encrypted_data = ciphertext[16:]

    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv))
    decryptor = cipher.decryptor()

    start = time.time()
    plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
    end = time.time()
    print(f"ECC Decryption Time: {end - start:.5f} seconds")

    return plaintext


# Compare performance with a file
file_path = "sample.txt"
with open(file_path, "wb") as f:
    f.write(b"A" * 1024 * 1024)  # Create a 1 MB file

# RSA Key Generation and Encryption/Decryption
rsa_key = generate_rsa_key()
rsa_public_key = rsa_key.publickey()
rsa_ciphertext = rsa_encrypt_file(file_path, rsa_public_key)
rsa_decrypted_data = rsa_decrypt_file(rsa_ciphertext, rsa_key)

# ECC Key Generation and Encryption/Decryption
ecc_key = generate_ecc_key()
ecc_peer_public_key = ecc_key.public_key()
ecc_ciphertext, sender_private_key = ecc_encrypt_file(
    file_path, ecc_peer_public_key)
ecc_decrypted_data = ecc_decrypt_file(
    ecc_ciphertext, sender_private_key, ecc_peer_public_key)

# Verification
assert rsa_decrypted_data == b"A" * 190, "RSA Decryption failed!"
assert ecc_decrypted_data == b"A" * 1024 * 1024, "ECC Decryption failed!"
