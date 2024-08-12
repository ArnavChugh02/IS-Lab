def decrypt_caesar_cipher(ciphertext, shift):
    decrypted_text = []
    for char in ciphertext:
        if char.isalpha():
            shift_amount = (ord(char) - ord('A') - shift) % 26
            decrypted_char = chr(shift_amount + ord('A'))
            decrypted_text.append(decrypted_char)
        else:
            decrypted_text.append(char)
    return ''.join(decrypted_text)

def find_shift(ciphertext, plaintext):
    shifts = []
    for c, p in zip(ciphertext, plaintext):
        if c.isalpha() and p.isalpha():
            shift = (ord(c) - ord(p)) % 26
            shifts.append(shift)
    if shifts:
        return shifts[0]
    return None

given_ciphertext = input("Enter sample cipher text: ")
given_plaintext = input("Enter sample plain text: ")

shift_value = find_shift(given_ciphertext, given_plaintext)

if shift_value is not None:
    ciphertext_to_decrypt = input("Enter message: ")

    decrypted_message = decrypt_caesar_cipher(ciphertext_to_decrypt, shift_value)
    
    print(f"Shift value: ", shift_value)
    print(f"Decrypted message: ", decrypted_message)
else:
    print("Unable to determine shift value.")
