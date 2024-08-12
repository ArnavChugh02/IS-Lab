def encrypt(plainText, key):
    cypherText = ""

    for char in plainText:
        start = ord('a') if char.islower() else ord('A')
        cypherChar = chr((ord(char) - start + key) % 26 + start)
        cypherText += cypherChar
    
    return cypherText

def decrypt(cypherText, key):
    decryptText = ""
    
    for char in cypherText:
        start = ord('a') if char.islower() else ord('A')
        plainChar = chr((ord(char) - start - key) % 26 + start)
        decryptText += plainChar
        
    return decryptText

mess = input("Enter the plain Text: ")
message = mess.replace(" ", "").lower()

key = int(input("Enter key: "))

enc_msg = encrypt(message, key)
print("Encrypted message: ", enc_msg)

dec_msg = decrypt(enc_msg, key)
print("Decrypted message: ", dec_msg)