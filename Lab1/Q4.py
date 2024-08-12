import numpy as np # type: ignore

def prepare_message(message):
    message = message.upper().replace(" ", "")
    if len(message) % 2 != 0:
        message += 'X'
    return [message[i:i+2] for i in range(0, len(message), 2)]

def convert_to_numbers(blocks):
    return [[ord(char) - ord('A') for char in block] for block in blocks]

def convert_to_chars(numbers):
    return ''.join(chr(num + ord('A')) for num in numbers)

def hill_encrypt(message_blocks, key_matrix):
    encrypted_blocks = []
    for block in message_blocks:
        block_numbers = convert_to_numbers([block])[0]
        encrypted_block = np.dot(key_matrix, block_numbers) % 26
        encrypted_blocks.extend(encrypted_block)
    return convert_to_chars(encrypted_blocks)

key = np.array([[3, 3], [2, 7]])
message = input("Enter message: ")
message_blocks = prepare_message(message)

encrypted_message = hill_encrypt(message_blocks, key)
print(f"Encrypted message: ", encrypted_message)
