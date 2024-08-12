def mod_inverse(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("No modular inverse exists")

def encrypt(plainText, key1, key2):
    cypherText = ""

    for char in plainText:
        start = ord('a') if char.islower() else ord('A')
        cypherChar = chr(((ord(char) - start)*key1 + key2) % 26 + start)
        cypherText += cypherChar
    
    return cypherText

def decrypt(cypherText, key1, key2):
    decryptText = ""
    inv_key = mod_inverse(key1, 26)
    
    for char in cypherText:
        start = ord('a') if char.islower() else ord('A')
        plainChar = chr((((ord(char) - start) - key2)*inv_key) % 26 + start)
        decryptText += plainChar
        
    return decryptText

mess = input("Enter the plain Text: ")
message = mess.replace(" ", "")

key1 = int(input("Enter key 1: "))
key2 = int(input("Enter key 2: "))

enc_msg = encrypt(message, key1, key2)
print("Encrypted message: ", enc_msg)

dec_msg = decrypt(enc_msg, key1, key2)
print("Decrypted message: ", dec_msg)