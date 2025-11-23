import hashlib

# test = "hello world"
# hash_object = hashlib.sha256(test.encode())
# hash_digest = hash_object.hexdigest()
# print("The hash of " + test + " is: " + hash_digest)

def hash_file(file_path):
    h = hashlib.new('sha256')
    with open(file_path, 'rb') as file:
        while True:
            chunk = file.read(1024)
            if chunk == b'':
                break
            h.update(chunk)
    return h.hexdigest()

def verify_integrity(file1, file2):
    hash1 = hash_file(file1)
    hash2 = hash_file(file2)
    print(f"\nChecking the file integrity of {file1} and {file2}...")
    if hash1 == hash2:
        return "File is intact and unaltered."
    return "File has been altered or corrupted."


if __name__ == "__main__":
    print(f"The hash of the file is : {hash_file(r'D:/nicov/Documents/OneDrive/Desktop/Code/Cryptography/sample_files/sample.txt')}")
    print(verify_integrity(r"D:/nicov/Documents/OneDrive/Desktop/Code/Cryptography/sample_files/HACKER_Profile 1.jpeg", r"D:/nicov/Documents/OneDrive/Desktop/Code/Cryptography/sample_files/HACKER_Profile 2.jpeg"))
    print(verify_integrity(r"D:/nicov/Documents/OneDrive/Desktop/Code/Cryptography/sample_files/HACKER_Profile 1.jpeg", r"D:/nicov/Documents/OneDrive/Desktop/Code/Cryptography/sample_files/HACKER_Profile 3.jpg"))
