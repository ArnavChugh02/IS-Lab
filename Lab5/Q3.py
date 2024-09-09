import hashlib
import time
import random
import string
from collections import defaultdict

def generate_random_string(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def compute_hashes(data, hash_functions):
    results = {name: [] for name in hash_functions}
    
    for hash_function in hash_functions:
        hasher = hash_functions[hash_function]()
        start_time = time.time()
        
        for item in data:
            hasher.update(item.encode())
            results[hash_function].append(hasher.hexdigest())
        
        end_time = time.time()
        results[hash_function+'_time'] = end_time - start_time
        
    return results

def detect_collisions(hashes):
    collision_info = defaultdict(list)
    
    for hash_name in hashes:
        if '_time' in hash_name:
            continue
        seen_hashes = {}
        for index, h in enumerate(hashes[hash_name]):
            if h in seen_hashes:
                collision_info[hash_name].append((seen_hashes[h], index))
            seen_hashes[h] = index
    
    return collision_info

def main():
    num_strings = 100
    string_length = 10

    data = [generate_random_string(string_length) for _ in range(num_strings)]

    hash_functions = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256
    }

    results = compute_hashes(data, hash_functions)

    collisions = detect_collisions(results)

    for hash_name in hash_functions:
        print(f"\n{hash_name.upper()} Computation Time: {results[hash_name+'_time']} seconds")
        if collisions[hash_name]:
            print(f"Collisions detected in {hash_name.upper()}:")
            for col in collisions[hash_name]:
                print(f"  Collision between indices: {col}")
        else:
            print(f"No collisions detected in {hash_name.upper()}.")

if __name__ == '__main__':
    main()
