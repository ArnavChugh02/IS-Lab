from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import binascii

# Temporary in-memory database for patient records
patients_db = {}

# Temporary in-memory database for storing keys (doctor's public key and private key)
keys_db = {}

# Base User class
class User:
    def __init__(self, name):
        self.name = name

    def view_patients(self):
        if patients_db:
            for patient_id, data in patients_db.items():
                print(f"Patient ID: {patient_id}, Name: {data['name']}, Disease: {data['disease']}")
        else:
            print("No patient records available.")

# Doctor class (inherits from User)
class Doctor(User):
    def __init__(self, name):
        super().__init__(name)
        self.rsa_private_key, self.rsa_public_key = self.generate_rsa_keys()
        # Store doctor's public key and private key globally in keys_db for simplicity
        keys_db['doctor_public_key'] = self.rsa_public_key
        keys_db['doctor_private_key'] = self.rsa_private_key
        print(f"Doctor {name}'s public key has been stored.")

    def generate_rsa_keys(self):
        key = RSA.generate(2048)
        private_key = key
        public_key = key.publickey()
        return private_key, public_key

    def encrypt_data(self, patient_id):
        if patient_id in patients_db:
            patient_data = f"{patients_db[patient_id]['name']}, {patients_db[patient_id]['disease']}".encode()
            cipher = PKCS1_OAEP.new(self.rsa_public_key)
            ciphertext = cipher.encrypt(patient_data)
            patients_db[patient_id]['ciphertext'] = binascii.hexlify(ciphertext).decode()
            print(f"Data encrypted for patient ID {patient_id}")
        else:
            print("Patient not found.")

    def sign_data(self, patient_id):
        if patient_id in patients_db and 'ciphertext' in patients_db[patient_id]:
            hashed_data = SHA256.new(patients_db[patient_id]['ciphertext'].encode())
            signature = pkcs1_15.new(self.rsa_private_key).sign(hashed_data)
            patients_db[patient_id]['signature'] = binascii.hexlify(signature).decode()
            print(f"Data signed for patient ID {patient_id}")
        else:
            print("Patient not found or data not encrypted.")

# Nurse class (inherits from User)
class Nurse(User):
    def __init__(self, name):
        super().__init__(name)

    def decrypt_data(self, patient_id):
        if 'doctor_private_key' not in keys_db:
            print("Doctor's private key not available. Doctor must log in first.")
            return

        doctor_private_key = keys_db['doctor_private_key']
        if patient_id in patients_db and 'ciphertext' in patients_db[patient_id]:
            ciphertext = binascii.unhexlify(patients_db[patient_id]['ciphertext'])
            cipher = PKCS1_OAEP.new(doctor_private_key)
            try:
                decrypted_data = cipher.decrypt(ciphertext)
                print(f"Decrypted data for patient ID {patient_id}: {decrypted_data.decode()}")
            except ValueError:
                print("Failed to decrypt the data. Invalid key or corrupted data.")
        else:
            print("Patient data not encrypted or not found.")

    def verify_signature(self, patient_id):
        if 'doctor_public_key' not in keys_db:
            print("Doctor's public key not available. Doctor must log in first.")
            return

        doctor_public_key = keys_db['doctor_public_key']
        if patient_id in patients_db and 'signature' in patients_db[patient_id]:
            hashed_data = SHA256.new(patients_db[patient_id]['ciphertext'].encode())
            signature = binascii.unhexlify(patients_db[patient_id]['signature'])
            try:
                pkcs1_15.new(doctor_public_key).verify(hashed_data, signature)
                print(f"Signature for patient ID {patient_id} is valid.")
            except (ValueError, TypeError):
                print("Signature verification failed.")
        else:
            print("Signature not found.")

# Admin class (inherits from User)
class Admin(User):
    def __init__(self, name):
        super().__init__(name)

    def verify_signature(self, patient_id):
        if 'doctor_public_key' not in keys_db:
            print("Doctor's public key not available. Doctor must log in first.")
            return

        doctor_public_key = keys_db['doctor_public_key']
        if patient_id in patients_db and 'signature' in patients_db[patient_id]:
            hashed_data = SHA256.new(patients_db[patient_id]['ciphertext'].encode())
            signature = binascii.unhexlify(patients_db[patient_id]['signature'])
            try:
                pkcs1_15.new(doctor_public_key).verify(hashed_data, signature)
                print(f"Signature for patient ID {patient_id} is valid.")
            except (ValueError, TypeError):
                print("Signature verification failed.")
        else:
            print("Signature not found.")

# Menu-driven program
def hospital_system():
    while True:
        print("\n--- Hospital System ---")
        print("1. Enter patient data")
        print("2. Doctor login")
        print("3. Nurse login")
        print("4. Admin login")
        print("5. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            patient_id = input("Enter patient ID: ")
            patient_name = input("Enter patient name: ")
            patient_disease = input("Enter patient disease: ")
            patients_db[patient_id] = {'name': patient_name, 'disease': patient_disease}
            print(f"Patient {patient_name} with disease {patient_disease} added to database.")

        elif choice == "2":
            doctor_name = input("Enter doctor's name: ")
            doctor = Doctor(doctor_name)
            while True:
                print("\n--- Doctor Menu ---")
                print("1. View patients")
                print("2. Encrypt patient data")
                print("3. Sign patient data")
                print("4. Logout")

                doc_choice = input("Enter your choice: ")

                if doc_choice == "1":
                    doctor.view_patients()
                elif doc_choice == "2":
                    patient_id = input("Enter patient ID to encrypt: ")
                    doctor.encrypt_data(patient_id)
                elif doc_choice == "3":
                    patient_id = input("Enter patient ID to sign: ")
                    doctor.sign_data(patient_id)
                elif doc_choice == "4":
                    print("Doctor logged out.")
                    break

        elif choice == "3":
            nurse_name = input("Enter nurse's name: ")
            nurse = Nurse(nurse_name)

            while True:
                print("\n--- Nurse Menu ---")
                print("1. View patients")
                print("2. Decrypt patient data")
                print("3. Verify signature")
                print("4. Logout")

                nurse_choice = input("Enter your choice: ")

                if nurse_choice == "1":
                    nurse.view_patients()
                elif nurse_choice == "2":
                    patient_id = input("Enter patient ID to decrypt: ")
                    nurse.decrypt_data(patient_id)
                elif nurse_choice == "3":
                    patient_id = input("Enter patient ID to verify signature: ")
                    nurse.verify_signature(patient_id)
                elif nurse_choice == "4":
                    print("Nurse logged out.")
                    break

        elif choice == "4":
            admin_name = input("Enter admin's name: ")
            admin = Admin(admin_name)

            while True:
                print("\n--- Admin Menu ---")
                print("1. View patients")
                print("2. Verify signature")
                print("3. Logout")

                admin_choice = input("Enter your choice: ")

                if admin_choice == "1":
                    admin.view_patients()
                elif admin_choice == "2":
                    patient_id = input("Enter patient ID to verify signature: ")
                    admin.verify_signature(patient_id)
                elif admin_choice == "3":
                    print("Admin logged out.")
                    break

        elif choice == "5":
            print("Exiting the system.")
            break

        else:
            print("Invalid choice. Try again.")

# Run the system
if __name__ == "__main__":
    hospital_system()
