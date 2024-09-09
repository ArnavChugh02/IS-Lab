from cryptography.hazmat.primitives.asymmetric import rsa, dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
# Key management
class KeyManager:
    def __init__(self):
        self.keys = {}

    def generate_rsa_keypair(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        return private_key, public_key

    def serialize_key(self, key, is_private=True):
        if is_private:
            return key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        else:
            return key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

    def load_key(self, key_data, is_private=True):
        if is_private:
            return serialization.load_pem_private_key(key_data, password=None)
        else:
            return serialization.load_pem_public_key(key_data)

    def store_key(self, system_id, key, is_private=True):
        self.keys[system_id] = (self.serialize_key(key, is_private), is_private)

    def get_key(self, system_id):
        if system_id in self.keys:
            return self.load_key(self.keys[system_id][0], self.keys[system_id][1])
        else:
            raise KeyError("Key not found for system_id")

# Diffie-Hellman Key Exchange
class DiffieHellman:
    def __init__(self):
        self.parameters = dh.generate_parameters(generator=2, key_size=2048)
    
    def generate_keypair(self):
        private_key = self.parameters.generate_private_key()
        public_key = private_key.public_key()
        return private_key, public_key

    def compute_shared_key(self, private_key, peer_public_key):
        return private_key.exchange(peer_public_key)

# Encryption and Decryption
class SecureCommunication:
    def __init__(self):
        self.key_manager = KeyManager()
        self.dh = DiffieHellman()

    def encrypt_message(self, message, symmetric_key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message) + encryptor.finalize()
        return iv + encrypted_message

    def decrypt_message(self, encrypted_message, symmetric_key):
        iv = encrypted_message[:16]
        ciphertext = encrypted_message[16:]
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_message

    def perform_key_exchange(self):
        private_key_a, public_key_a = self.dh.generate_keypair()
        private_key_b, public_key_b = self.dh.generate_keypair()
        shared_key_a = self.dh.compute_shared_key(private_key_a, public_key_b)
        shared_key_b = self.dh.compute_shared_key(private_key_b, public_key_a)
        assert shared_key_a == shared_key_b
        symmetric_key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=os.urandom(16), iterations=100000).derive(shared_key_a)
        return symmetric_key

def main():
    # Initialize secure communication
    communication = SecureCommunication()

    # Generate RSA key pairs for subsystems
    finance_private_key, finance_public_key = communication.key_manager.generate_rsa_keypair()
    hr_private_key, hr_public_key = communication.key_manager.generate_rsa_keypair()
    supply_chain_private_key, supply_chain_public_key = communication.key_manager.generate_rsa_keypair()

    # Store keys
    communication.key_manager.store_key("finance", finance_private_key)
    communication.key_manager.store_key("hr", hr_private_key)
    communication.key_manager.store_key("supply_chain", supply_chain_private_key)

    # Perform Diffie-Hellman key exchange
    symmetric_key = communication.perform_key_exchange()

    # Encrypt and decrypt message
    message = b"Confidential Report"
    encrypted_message = communication.encrypt_message(message, symmetric_key)
    decrypted_message = communication.decrypt_message(encrypted_message, symmetric_key)

    # Print results
    print(f"Original message: {message.decode()}")
    print(f"Encrypted message (base64): {base64.b64encode(encrypted_message).decode()}")
    print(f"Decrypted message: {decrypted_message.decode()}")

if __name__ == '__main__':
    main()
