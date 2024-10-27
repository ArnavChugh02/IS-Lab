import random
import sympy
from sympy import mod_inverse


def genprime(bits=16):
    while True:
        p = random.getrandbits(bits)
        if sympy.isprime(p):
            return p

def L(u,n):
    return (u - 1) // n
def genkeypair():
    p = genprime()
    q = genprime()
    n = p * q
    lam = sympy.lcm(p - 1, q - 1)
    g = random.randint(1, n * n)

    lam = int(lam)
    mu = mod_inverse(L(pow(g, lam, n * n),n), n)

    return (n, g), (lam, mu)


def encrypt(pubk, msg):
    n, g = pubk
    while True:
        r = random.randint(1, n - 1)
        if sympy.gcd(r, n) == 1:
            break
    c = (pow(g, msg, n * n) * pow(r, n, n * n)) % (n * n)
    return c


def decrypt(prik, ct, pubk):
    n, _ = pubk
    lam, mu = prik
    msg = (L(pow(ct, lam, n * n),n) * mu) % n
    return msg


def homadd(c1, c2, pubk):
    n, _ = pubk
    return (c1 * c2) % (n * n)


if __name__ == "__main__":
    num1 = 17
    num2 = 20

    pubk, prik = genkeypair()

    c1 = encrypt(pubk, num1)
    c2 = encrypt(pubk, num2)
    print(f"Ciphertext1: {c1}")
    print(f"Ciphertext2: {c2}")

    c = homadd(c1, c2, pubk)
    print(f"Encrypted sum: {c}")

    dec = decrypt(prik, c, pubk)
    print(f"Decrypted sum: {dec}")

    print(f"Original sum: {num1 + num2}")








# import random
# from sympy import mod_inverse

# # Paillier Key Generation
# def generate_paillier_keys(bits=512):
#     p = random_prime(bits)
#     q = random_prime(bits)
#     n = p * q
#     nsquare = n ** 2
#     g = n + 1  # Common choice for g
#     lambd = (p - 1) * (q - 1)  # λ(n) = lcm(p-1, q-1)
#     mu = mod_inverse(lambd, n)  # μ = λ(n)^{-1} mod n
#     return (n, g), (lambd, mu, n, nsquare)

# # Random prime generator
# def random_prime(bits):
#     return random.getrandbits(bits) | 1

# # Paillier Encryption: c = g^m * r^n mod n^2
# def paillier_encrypt(public_key, message):
#     n, g = public_key
#     nsquare = n ** 2
#     r = random.randint(1, n - 1)  # Random value r
#     c = (pow(g, message, nsquare) * pow(r, n, nsquare)) % nsquare
#     return c

# # Paillier Decryption: m = L(c^λ mod n^2) * μ mod n
# def paillier_decrypt(private_key, ciphertext):
#     lambd, mu, n, nsquare = private_key
#     c_lambd = pow(ciphertext, lambd, nsquare)
#     l = (c_lambd - 1) // n
#     m = (l * mu) % n
#     return m

# # Homomorphic addition: c_sum = c1 * c2 mod n^2
# def homomorphic_add(c1, c2, public_key):
#     n, g = public_key
#     nsquare = n ** 2
#     return (c1 * c2) % nsquare

# # Test Paillier Homomorphic Encryption
# if __name__ == "__main__":
#     # Generate Paillier keys
#     public_key, private_key = generate_paillier_keys(bits=128)
    
#     # Original integers to be encrypted
#     m1 = 7
#     m2 = 3
#     print(f"Original integers: {m1}, {m2}")
    
#     # Encrypt the integers
#     c1 = paillier_encrypt(public_key, m1)
#     c2 = paillier_encrypt(public_key, m2)
#     print(f"Ciphertext of {m1}: {c1}")
#     print(f"Ciphertext of {m2}: {c2}")
    
#     # Perform addition on the encrypted values
#     encrypted_sum = homomorphic_add(c1, c2, public_key)
#     print(f"Encrypted sum: {encrypted_sum}")
    
#     # Decrypt the result
#     decrypted_sum = paillier_decrypt(private_key, encrypted_sum)
#     print(f"Decrypted sum: {decrypted_sum}")
    
#     # Verify the result
#     expected_sum = m1 + m2
#     print(f"Expected sum: {expected_sum}")
    
#     if decrypted_sum == expected_sum:
#         print("Decryption is correct, the additive homomorphic property holds.")
#     else:
#         print("Something went wrong!")

