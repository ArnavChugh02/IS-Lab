import socket
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import binascii


# Function to perform SHA-256 hashing
def hash_data(data):
    sha256 = SHA256.new(data)
    return sha256.hexdigest()


# Function to generate RSA keys for digital signature
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key


# Function to digitally sign the data using RSA private key
def sign_data(private_key, data):
    hashed_data = SHA256.new(data)
    signature = pkcs1_15.new(private_key).sign(hashed_data)
    return binascii.hexlify(signature).decode()


# ECC encryption function
def ecc_encrypt(data, ecc_key):
    shared_key = ecc_key.pointQ * ecc_key.d
    shared_key_bytes = shared_key.xy[0].to_bytes()
    cipher = AES.new(shared_key_bytes[:16], AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return binascii.hexlify(ciphertext).decode()


def server_program():
    # Setup the socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = '127.0.0.1'  # localhost
    port = 65432
    server_socket.bind((host, port))

    server_socket.listen(1)
    print("Server is listening on port", port)

    conn, addr = server_socket.accept()
    print("Connected by", addr)

    # Receive the data
    data = conn.recv(1024).decode()

    if not data:
        print("No data received")
        conn.close()
        return

    print(f"Message received from client: {data}")

    # Perform ECC encryption (double-layered)
    ecc_key = ECC.generate(curve='P-256')
    encrypted_data_1 = ecc_encrypt(data.encode(), ecc_key)
    encrypted_data_2 = ecc_encrypt(encrypted_data_1.encode(), ecc_key)

    # Generate RSA keys and sign the encrypted data
    rsa_private_key, rsa_public_key = generate_rsa_keys()
    digital_signature = sign_data(rsa_private_key, encrypted_data_2.encode())

    # Compute hash (SHA-256)
    data_hash = hash_data(data.encode())

    # Send all results back to client
    response = f"Double-layered ECC encryption: {encrypted_data_2}\n"
    response += f"RSA digital signature: {digital_signature}\n"
    response += f"SHA-256 hash: {data_hash}\n"

    conn.sendall(response.encode())
    conn.close()


if __name__ == '__main__':
    server_program()
