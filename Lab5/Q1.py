def simple_hash(input_string):
    hash_value = 5381

    for char in input_string:
        hash_value = (hash_value * 33 + ord(char)) & 0xFFFFFFFF
    
    return hash_value

input_string = input("Enter string: ")
hash_result = simple_hash(input_string)
print(f"Hash value for '{input_string}': {hash_result}")
