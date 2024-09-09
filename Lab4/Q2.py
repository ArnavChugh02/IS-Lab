import logging
import os
import pickle
from sympy import nextprime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

# Configure logging
logging.basicConfig(filename='key_management.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Helper function to generate large prime numbers
def generate_large_prime(bits):
    # Generate a prime number of approximately 'bits' size
    start = 2**(bits - 1)
    prime = nextprime(start)
    while prime.bit_length() < bits:
        prime = nextprime(prime)
    return prime

# Key management service
class KeyManagementService:
    def __init__(self):
        self.keys = {}
        self.file_path = 'keys.dat'
        self.load_keys()

    def generate_keypair(self, bits=1024):
        p = generate_large_prime(bits // 2)
        q = generate_large_prime(bits // 2)
        n = p * q
        public_key = (n, p, q)
        private_key = (p, q)
        return public_key, private_key

    def store_keys(self, hospital_id, public_key, private_key):
        self.keys[hospital_id] = (public_key, private_key)
        self.save_keys()
        logging.info(f'Keys generated and stored for {hospital_id}')

    def get_keys(self, hospital_id):
        if hospital_id in self.keys:
            return self.keys[hospital_id]
        else:
            logging.error(f'Keys not found for {hospital_id}')
            return None

    def revoke_keys(self, hospital_id):
        if hospital_id in self.keys:
            del self.keys[hospital_id]
            self.save_keys()
            logging.info(f'Keys revoked for {hospital_id}')
        else:
            logging.error(f'Keys not found for {hospital_id}')

    def renew_keys(self, hospital_id):
        if hospital_id in self.keys:
            public_key, _ = self.generate_keypair()
            self.keys[hospital_id] = (public_key, self.keys[hospital_id][1])
            self.save_keys()
            logging.info(f'Keys renewed for {hospital_id}')
        else:
            logging.error(f'Keys not found for {hospital_id}')

    def save_keys(self):
        with open(self.file_path, 'wb') as f:
            pickle.dump(self.keys, f)

    def load_keys(self):
        if os.path.exists(self.file_path):
            with open(self.file_path, 'rb') as f:
                self.keys = pickle.load(f)

    def perform_audit(self):
        logging.info('Performing audit of all keys')
        for hospital_id, (pub_key, _) in self.keys.items():
            logging.info(f'Hospital ID: {hospital_id}, Public Key: {pub_key}')

# Example usage
def main():
    kms = KeyManagementService()

    # Generate and store keys for hospitals and clinics
    hospital_ids = ['hospital1', 'clinic1', 'hospital2']
    for hospital_id in hospital_ids:
        public_key, private_key = kms.generate_keypair()
        kms.store_keys(hospital_id, public_key, private_key)

    # Request and use keys
    for hospital_id in hospital_ids:
        keys = kms.get_keys(hospital_id)
        if keys:
            print(f'Keys for {hospital_id}: {keys}')

    # Revoke keys
    kms.revoke_keys('clinic1')

    # Renew keys
    kms.renew_keys('hospital1')

    # Perform an audit
    kms.perform_audit()

if __name__ == '__main__':
    main()
