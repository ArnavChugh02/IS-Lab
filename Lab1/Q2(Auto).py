def autokey_encrypt(plaintext, key):
    key = int(key)  
    plaintext = plaintext.upper().replace(" ", "") 
    ciphertext = []

    extended_key = [key]
    
    for char in plaintext:
        if char.isalpha():
            shift = extended_key[-1]  
            encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            ciphertext.append(encrypted_char)
            extended_key.append(ord(encrypted_char) - ord('A'))  
        else:
            ciphertext.append(char)
    
    return ''.join(ciphertext)

def autokey_decrypt(ciphertext, key):
    key = int(key) 
    ciphertext = ciphertext.upper().replace(" ", "")
    plaintext = []

    extended_key = [key]
    
    for char in ciphertext:
        if char.isalpha():
            shift = extended_key[-1]  
            decrypted_char = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            plaintext.append(decrypted_char)
            extended_key.append(ord(decrypted_char) - ord('A'))  
        else:
            plaintext.append(char)
    
    return ''.join(plaintext)

plainText = input("Enter the plain text: ")
key = input("Enter key: ")

enc_msg = autokey_encrypt(plainText, key)
print("Encrypted message: ", enc_msg)

dec_msg = autokey_decrypt(enc_msg, key)
print("Decrypted message: ", dec_msg)

