def vigenere_encrypt(plaintext, key):
    key = key.upper()
    plaintext = plaintext.upper()
    key_length = len(key)
    ciphertext = []
    
    for i, char in enumerate(plaintext):
        if char.isalpha():
            shift = ord(key[i % key_length]) - ord('A')
            encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            ciphertext.append(encrypted_char)
        else:
            ciphertext.append(char)
    
    return ''.join(ciphertext)

def vignere_decrypt(ciphertext, key):
    key = key.upper()
    ciphertext = ciphertext.upper()
    key_length = len(key)
    plaintext = []
    
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            shift = ord(key[i % key_length]) - ord('A')
            decrypted_char = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            plaintext.append(decrypted_char)
        else:
            plaintext.append(char)
            
    return ''.join(plaintext)

plainText = input("Enter the plain text: ")
key = input("Enter the key: ")
plainText = plainText.replace(" ", "")

enc_msg = vigenere_encrypt(plainText, key)
enc_msg = enc_msg.lower()
print("Encypted message: ", enc_msg)

dec_msg = vignere_decrypt(enc_msg, key)
dec_msg = dec_msg.lower()
print("Decrypted message: ", dec_msg)


