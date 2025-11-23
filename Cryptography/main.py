from modules.hash import hash_file, verify_integrity
from modules.encryption import aes_ed, rsa_ed
from modules.password import check_password_strength, hash_password, verify_password
from getpass import getpass

def menu():
    print("\nSelect an option:")
    print("1. Hash a file")
    print("2. Verify file integrity")
    print("3. AES Encryption/Decryption")
    print("4. RSA Encryption/Decryption")
    print("5. Password Manager")
    print("6. Exit")
    
print("Welcome to the Cryptography Toolkit v1.0")

while True:
    menu()
    choice = input("\nEnter your choice (1-6): ")
    if choice == "1":
        file_path = input("Enter the file path to hash: ")
        print(f"The hash of the file is : {hash_file(file_path)}")
    elif choice == "2":
        file1 = input("Enter the path of the first file: ")
        file2 = input("Enter the path of the second file: ")
        print(verify_integrity(file1, file2))
    elif choice == "3":
        message = input("Enter the message to encrypt with AES: ").encode()
        key, ciphertext, plaintext = aes_ed(message)
        print("AES-GCM Encryption")
        print("Key:", key)
        print("Ciphertext:", ciphertext)
        print("Plaintext:", plaintext)
    elif choice == "4":
        message = input("Enter the message to encrypt with RSA: ")
        ciphertext, plaintext = rsa_ed(message)
        print("RSA Encryption")
        print("Ciphertext:", ciphertext)
        print("Plaintext:", plaintext)
    elif choice == "5":
        while True:
            password = getpass("Enter a password to check its strength: ")
            strength_response = check_password_strength(password)
            print(strength_response)
            if strength_response.startswith("Weak password"):
                print("Please try again with a stronger password.\n")
            else:
                break
        
        hashed_password = hash_password(password)
        print(f"Hashed Password: {hashed_password}")
        attempt = getpass("Re-enter your password for verification: ")
        print(verify_password(attempt, hashed_password))
    elif choice == "6":
        print("\nExiting the Cryptography Toolkit.")
        break
    else:
        print("Invalid choice. Please select a valid option (1-6).")
        
print("Thank you for using the Cryptography Toolkit v1.0")