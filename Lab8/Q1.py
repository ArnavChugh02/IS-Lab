from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
from collections import defaultdict

# Generate a random key for AES encryption
key = os.urandom(16)  # AES-128
iv = os.urandom(16)   # Initialization vector

def encrypt_aes(plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the plaintext to make it a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    
    return encryptor.update(padded_data) + encryptor.finalize()

def decrypt_aes(ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpad the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    
    return unpadded_data.decode()

# Step 1a: Create a dataset
documents = {
    1: "the quick brown fox jumps over the lazy dog",
    2: "never gonna give you up never gonna let you down",
    3: "hello world this is a test document",
    4: "secure search engine with encrypted data",
    5: "data science is the future of technology",
    6: "python programming for data analysis",
    7: "machine learning and artificial intelligence",
    8: "the quick brown fox is clever",
    9: "data security is important for privacy",
    10: "encryption helps protect sensitive information"
}

# Step 1c: Create an inverted index
def create_inverted_index(docs):
    index = defaultdict(set)
    for doc_id, text in docs.items():
        words = text.split()
        for word in words:
            index[word].add(doc_id)
    return index

# Create the inverted index
inverted_index = create_inverted_index(documents)

# Encrypt the inverted index
encrypted_index = {encrypt_aes(word): encrypt_aes(",".join(map(str, doc_ids))) for word, doc_ids in inverted_index.items()}

# Display the encrypted index for debugging
print("Encrypted Index:")
for word, doc_ids in encrypted_index.items():
    print(f"{word.hex()}: {doc_ids.hex()}")

# Step 1d: Implement the search function
def search(query):
    encrypted_query = encrypt_aes(query)
    results = {}
    
    # Check the inverted index for the encrypted query
    for word, doc_ids_encrypted in encrypted_index.items():
        if encrypted_query == word:
            doc_ids = decrypt_aes(doc_ids_encrypted).split(",")
            results = {doc_id: documents[int(doc_id)] for doc_id in doc_ids}
            break

    return results

# Example search
query = "quick"
search_results = search(query)

# Output results
print("Search Results:")
if search_results:
    for doc_id, doc_text in search_results.items():
        print(f"Document ID {doc_id}: {doc_text}")
else:
    print("No documents found.")







from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from collections import defaultdict
import hashlib

# --- Sample Documents (Dataset) ---
documents = {
    1: "the cat is on the mat",
    2: "the dog is in the fog",
    3: "a quick brown fox jumped over the lazy dog",
    4: "the quick cat jumped over the dog",
    5: "lorem ipsum dolor sit amet",
    6: "sit amet lorem ipsum quick",
    7: "foxes are quick and sly",
    8: "dogs and cats are friendly",
    9: "friendly animals are kind",
    10: "the fox is in the hole"
}

# --- RSA Key Generation ---


def generate_rsa_keys(bits=2048):
    key = RSA.generate(bits)
    private_key = key
    public_key = key.publickey()
    return public_key, private_key

# --- RSA Encryption ---


def rsa_encrypt(public_key, message):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message.encode())
    return ciphertext

# --- RSA Decryption ---


def rsa_decrypt(private_key, ciphertext):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(ciphertext)
    return decrypted_message.decode()

# --- Hash Function ---


def hash_word(word):
    return hashlib.sha256(word.encode()).hexdigest()

# --- Create an Inverted Index ---


def create_inverted_index(documents):
    inverted_index = defaultdict(list)
    for doc_id, text in documents.items():
        for word in text.split():
            hashed_word = hash_word(word)  # Hash the words for indexing
            inverted_index[hashed_word].append(doc_id)
    return inverted_index

# --- Search Function ---


def search(query, inverted_index):
    hashed_query = hash_word(query)  # Hash the query before searching

    # Search in the inverted index
    if hashed_query in inverted_index:
        doc_ids = inverted_index[hashed_query]

        # Display the documents
        print(f"Search results for '{query}':")
        for doc_id in doc_ids:
            print(f"Document {doc_id}: {documents[doc_id]}")
    else:
        print(f"No results found for '{query}'.")


# --- Main Execution ---
if __name__ == "__main__":
    # Step 1: Generate RSA keys (for possible future encryption of documents)
    public_key, private_key = generate_rsa_keys()

    # Step 2: Create an inverted index from the dataset (with hashed words)
    inverted_index = create_inverted_index(documents)

    # Step 3: Take a search query from the user
    query = input("Enter search query: ")

    # Step 4: Perform the search on the hashed inverted index and display results
    search(query, inverted_index)
