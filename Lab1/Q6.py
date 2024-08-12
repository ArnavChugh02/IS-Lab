from math import gcd

def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def affine_decrypt(cypherText, key1, key2):
    decryptText = ""
    inv_key = mod_inverse(key1, 26)
    
    for char in cypherText:
        start = ord('a') if char.islower() else ord('A')
        plainChar = chr((((ord(char) - start) - key2)*inv_key) % 26 + start)
        decryptText += plainChar
        
    return decryptText

def brute_force_affine(ciphertext, known_plaintext, known_ciphertext):
    p1, p2 = known_plaintext
    c1, c2 = known_ciphertext

    p1, p2 = ord(p1) - ord('A'), ord(p2) - ord('A')
    c1, c2 = ord(c1) - ord('A'), ord(c2) - ord('A')

    for a in range(1, 26):
        if gcd(a, 26) == 1: 
            for b in range(0, 26):
                if (a * p1 + b) % 26 == c1 and (a * p2 + b) % 26 == c2:
                    print(f"Trying a={a}, b={b}")
                    decrypted_text = affine_decrypt(ciphertext, a, b)
                    print(f"Decrypted message with a={a} and b={b}: {decrypted_text}")

ciphertext = input("Enter cipher text: ")
known_plaintext = input("Enter known plain text: ")
known_ciphertext = input("Enter known cipher text: ")

brute_force_affine(ciphertext, known_plaintext, known_ciphertext)
