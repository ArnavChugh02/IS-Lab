from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64

private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

message = b"Secure Transactions"

shared_secret = private_key.exchange(ec.ECDH(), public_key)

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=os.urandom(16),
    iterations=100000,
)
symmetric_key = kdf.derive(shared_secret)

iv = os.urandom(16)
cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(message) + encryptor.finalize()

cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
decryptor = cipher.decryptor()
decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

print(f"Original message: {message.decode()}")
print(f"Ciphertext (base64): {base64.b64encode(ciphertext).decode()}")
print(f"Decrypted message: {decrypted_message.decode()}")
