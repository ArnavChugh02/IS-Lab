def create_playfair_matrix(key):
    key = key.upper().replace("J", "I")
    matrix = []
    used_chars = set()

    for char in key:
        if char not in used_chars and char.isalpha():
            used_chars.add(char)
            matrix.append(char)

    for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if char not in used_chars:
            matrix.append(char)
    
    return [matrix[i:i+5] for i in range(0, 25, 5)]

def prepare_message(message):
    message = message.upper().replace("J", "I").replace(" ", "")
    prepared_message = []
    
    i = 0
    while i < len(message):
        if i + 1 < len(message) and message[i] == message[i + 1]:
            prepared_message.append(message[i] + 'X')
            i += 1
        else:
            if i + 1 < len(message):
                prepared_message.append(message[i] + message[i + 1])
                i += 2
            else:
                prepared_message.append(message[i] + 'X')
                i += 1

    return prepared_message

def find_position(matrix, char):
    for r, row in enumerate(matrix):
        if char in row:
            return r, row.index(char)
    return None

def playfair_encrypt(message, key):
    matrix = create_playfair_matrix(key)
    prepared_message = prepare_message(message)
    ciphertext = []
    
    for pair in prepared_message:
        row1, col1 = find_position(matrix, pair[0])
        row2, col2 = find_position(matrix, pair[1])
        
        if row1 == row2:
            ciphertext.append(matrix[row1][(col1 + 1) % 5])
            ciphertext.append(matrix[row2][(col2 + 1) % 5])
        elif col1 == col2:
            ciphertext.append(matrix[(row1 + 1) % 5][col1])
            ciphertext.append(matrix[(row2 + 1) % 5][col2])
        else:
            ciphertext.append(matrix[row1][col2])
            ciphertext.append(matrix[row2][col1])
    
    return ''.join(ciphertext)

plainText = input("Enter the plain text: ")
key = input("Enter key: ")

enc_msg = playfair_encrypt(plainText, key)
print("Encrypted message: ", enc_msg)

