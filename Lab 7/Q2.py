import random
from sympy import mod_inverse, isprime
import sympy

def genprime(bits=16):
    """ Generate a prime number with the specified bit length. """
    while True:
        p = random.getrandbits(bits)
        if isprime(p):
            return p


def genkeypair(bits=16):
    """ Generate RSA public and private key pair. """
    p = genprime(bits)
    q = genprime(bits)
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Choose e such that 1 < e < phi_n and gcd(e, phi_n) = 1
    e = random.randint(2, phi_n - 1)
    while sympy.gcd(e, phi_n) != 1:
        e = random.randint(2, phi_n - 1)

    d = mod_inverse(e, phi_n)

    return (n, e), (n, d)  # Public key and private key


def encrypt(pubkey, plaintext):
    """ Encrypt a plaintext message using the public key. """
    n, e = pubkey
    return pow(plaintext, e, n)


def decrypt(privkey, ciphertext):
    """ Decrypt a ciphertext message using the private key. """
    n, d = privkey
    return pow(ciphertext, d, n)


def homomorphic_multiply(c1, c2, n):
    """ Multiply two ciphertexts under RSA encryption. """
    return (c1 * c2) % n


# Example usage
if __name__ == "__main__":
    num1 = 7
    num2 = 3

    pubkey, privkey = genkeypair()

    # Encrypt the numbers
    c1 = encrypt(pubkey, num1)
    c2 = encrypt(pubkey, num2)
    print(f"Ciphertext1: {c1}")
    print(f"Ciphertext2: {c2}")

    # Perform homomorphic multiplication
    c_product = homomorphic_multiply(c1, c2, pubkey[0])
    print(f"Encrypted product: {c_product}")

    # Decrypt the result
    dec_product = decrypt(privkey, c_product)
    print(f"Decrypted product: {dec_product}")

    # Verify the result
    print(f"Original product: {num1 * num2}")








# from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
# import random

# # RSA Key Generation


# def generate_rsa_keys(bits=512):
#     e = 65537  # Common choice for public exponent
#     p = getPrime(bits)
#     q = getPrime(bits)
#     n = p * q
#     phi_n = (p - 1) * (q - 1)

#     d = inverse(e, phi_n)  # Private key
#     return (n, e), (n, d)  # Return public and private keys

# # RSA Encryption: c = m^e mod n


# def rsa_encrypt(public_key, message):
#     n, e = public_key
#     ciphertext = pow(message, e, n)
#     return ciphertext

# # RSA Decryption: m = c^d mod n


# def rsa_decrypt(private_key, ciphertext):
#     n, d = private_key
#     message = pow(ciphertext, d, n)
#     return message

# # Multiplicative Homomorphism: c1 * c2 mod n


# def homomorphic_multiply(c1, c2, n):
#     return (c1 * c2) % n


# # Test RSA Homomorphic Encryption
# if __name__ == "__main__":
#     # Generate RSA keys
#     public_key, private_key = generate_rsa_keys(bits=512)

#     # Original integers to be encrypted
#     m1 = input("Enter the first character: ")
#     m2 = input("Enter the second character: ")
#     print(f"Original integers: {ord(m1)}, {ord(m2)}")

#     n1 = ord(m1)
#     n2 = ord(m2)

#     # Encrypt the integers
#     c1 = rsa_encrypt(public_key, n1)
#     c2 = rsa_encrypt(public_key, n2)
#     print(f"Ciphertext of {m1}: {c1}")
#     print(f"Ciphertext of {m2}: {c2}")

#     # Perform multiplication on the encrypted values
#     encrypted_product = homomorphic_multiply(c1, c2, public_key[0])
#     print(f"Encrypted product: {encrypted_product}")

#     # Decrypt the result
#     decrypted_product = rsa_decrypt(private_key, encrypted_product)
#     print(f"Decrypted product: {chr(decrypted_product)}")

#     # Verify the result
#     expected_product = n1 * n2
#     print(f"Expected product: {chr(expected_product)}")

#     if decrypted_product == expected_product:
#         print("Decryption is correct, the homomorphic property holds.")
#     else:
#         print("Something went wrong!")

