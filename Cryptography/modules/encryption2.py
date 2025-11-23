import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

'''
#Encryption steps:
1. Atbash Cipher
2. Substitution Cipher
3. Vigenère Cipher
4. AES Encryption
5. RSA Encryption
6. To Binary
7. To Gray Code
8. What ever else you want to add

#Decryption steps:
1. From what ever else you want to add
2. From Gray Code
3. From Binary
4. RSA Decryption
5. AES Decryption
6. Vigenère Decipher
7. Substitution Decipher
8. Atbash Decipher
'''

def main():
    plain_text = input("Enter the text to encrypt: ")
    key_substitution = "QWERTYUIOPASDFGHJKLZXCVBNM"  # Example substitution key
    key_vigenere = "JUMBOHACKER"  # Example Vigenère key
    print("\n--- Encryption Process ---")
    atbash_encrypted = atbash_encrypt(plain_text)
    print("Atbash ->", atbash_encrypted)
    substitution_encrypted = substitution_encrypt(atbash_encrypted, key_substitution)
    print("Substitution ->", substitution_encrypted)
    vigenere_encrypted = vigenere_encrypt(substitution_encrypted, key_vigenere)
    print("Vigenère ->", vigenere_encrypted)
    aes_key, aes_ciphertext = aes_encrypt(vigenere_encrypted)
    print("AES key (hex) ->", aes_key)
    print("AES ciphertext (hex) ->", aes_ciphertext[:60] + ('...' if len(aes_ciphertext)>60 else ''))
    # aes_key is hex string, aes_ciphertext is hex string
    aes_key_bytes = bytes.fromhex(aes_key)                       # raw AES key
    # RSA-encrypt the AES key (hybrid scheme). rsa_encrypted_key is hex string
    rsa_private_key, rsa_encrypted_key = rsa_encrypt_key(aes_key_bytes)
    # store rsa_encrypted_key (hex) + aes_ciphertext (hex)
    binary_data = to_binary(rsa_encrypted_key)
    # binary_to_gray expects a continuous bitstring (no spaces)
    gray_code = binary_to_gray(binary_data.replace(' ', ''))
    print("RSA-encrypted AES key (hex) ->", rsa_encrypted_key[:60] + ('...' if len(rsa_encrypted_key)>60 else ''))
    print("Final Encrypted Data (Gray Code):", gray_code[:120] + ('...' if len(gray_code)>120 else ''))

    print("\n--- Decryption Process ---")
    binary_from_gray = gray_to_binary(gray_code)
    rsa_ciphertext_from_binary = from_binary(binary_from_gray)
    print("RSA ciphertext recovered (hex) ->", rsa_ciphertext_from_binary[:60] + ('...' if len(rsa_ciphertext_from_binary)>60 else ''))
    # rsa_ciphertext_from_binary is the hex string of the RSA-encrypted AES key
    aes_key_bytes_decrypted = rsa_decrypt_key(rsa_private_key, rsa_ciphertext_from_binary)
    print("AES key recovered (hex) ->", aes_key_bytes_decrypted.hex())
    aes_key_hex_decrypted = aes_key_bytes_decrypted.hex()
    # aes_ciphertext remains the hex string produced earlier
    vigenere_decrypted = aes_decrypt(aes_key_hex_decrypted, aes_ciphertext)
    print("After AES decrypt (Vigenère text) ->", vigenere_decrypted)
    substitution_decrypted = vigenere_decrypt(vigenere_decrypted, key_vigenere)
    print("After Vigenère decrypt ->", substitution_decrypted)
    after_substitution = substitution_decrypt(substitution_decrypted, key_substitution)
    print("After Substitution decrypt ->", after_substitution)
    atbash_decrypted = atbash_decrypt(after_substitution)
    print("After Atbash decrypt ->", atbash_decrypted)
    print("Final Decrypted Text:", atbash_decrypted)
    
#Encryption
#Atbash Cipher
def atbash_encrypt(plaintext):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    reversed_alphabet = alphabet[::-1]
    table = str.maketrans(alphabet + alphabet.lower(), reversed_alphabet + reversed_alphabet.lower())
    return plaintext.translate(table)

#Atbash Decipher
def atbash_decrypt(ciphertext):
    return atbash_encrypt(ciphertext)  # Atbash is symmetric

#Substitution Cipher
def substitution_encrypt(plaintext, key):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    table = str.maketrans(alphabet + alphabet.lower(), key.upper() + key.lower())
    return plaintext.translate(table)

#Substitution Decipher
def substitution_decrypt(ciphertext, key):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    table = str.maketrans(key.upper() + key.lower(), alphabet + alphabet.lower())
    return ciphertext.translate(table)

#Vigenère Cipher
def vigenere_encrypt(plaintext, key):
    encrypted = []
    key_length = len(key)
    for i, char in enumerate(plaintext):
        if char.isalpha():
            shift = ord(key[i % key_length].upper()) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            encrypted_char = chr((ord(char) - base + shift) % 26 + base)
            encrypted.append(encrypted_char)
        else:
            encrypted.append(char)
    return ''.join(encrypted)

#Vigenère Decipher
def vigenere_decrypt(ciphertext, key):
    decrypted = []
    key_length = len(key)
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            shift = ord(key[i % key_length].upper()) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            decrypted_char = chr((ord(char) - base - shift) % 26 + base)
            decrypted.append(decrypted_char)
        else:
            decrypted.append(char)
    return ''.join(decrypted)

#AES Encryption
def aes_encrypt(message):
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    aes = AESGCM(key)
    ciphertext = nonce + aes.encrypt(nonce, message.encode(), None)
    return key.hex(), ciphertext.hex()

#AES Decryption
def aes_decrypt(key_hex, ciphertext_hex):
    key = bytes.fromhex(key_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    nonce = ciphertext[:12]
    aes = AESGCM(key)
    plaintext = aes.decrypt(nonce, ciphertext[12:], None)
    return plaintext.decode()

#RSA Encryption
def rsa_encrypt(message):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return private_key, ciphertext.hex()

#RSA Encryption for key (hybrid scheme helper)
def rsa_encrypt_key(key_bytes):
    """
    Generate an RSA keypair and encrypt raw `key_bytes` with the public key.

    Returns (private_key, ciphertext_hex).
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    ciphertext = public_key.encrypt(
        key_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return private_key, ciphertext.hex()

#RSA Decryption for key (returns raw bytes)
def rsa_decrypt_key(private_key, ciphertext_hex):
    """
    Decrypt a hex-encoded RSA ciphertext and return the plaintext bytes.
    """
    ciphertext = bytes.fromhex(ciphertext_hex)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

#To Binary
def to_binary(data):
    """
    Convert a string or bytes to a space-separated binary representation
    of its ASCII/byte values (e.g. 'A' -> '01000001').
    """
    if isinstance(data, bytes):
        b = data
    else:
        b = str(data).encode()
    return ' '.join(format(byte, '08b') for byte in b)

#From Binary
def from_binary(binary_str):
    """
    Convert binary string to text. Accepts either space-separated 8-bit groups
    (e.g. '01000001 01000010') or a continuous bitstring ('0100000101000010').

    Returns the decoded string (each 8-bit chunk -> chr).
    """
    if not binary_str:
        return ''
    # Accept space-separated or continuous bitstring
    if ' ' in binary_str:
        bytes_list = binary_str.split()
    else:
        # chunk into 8-bit groups; if final chunk is short, pad with zeros
        if len(binary_str) % 8 != 0:
            pad_len = 8 - (len(binary_str) % 8)
            binary_str = binary_str + ('0' * pad_len)
        bytes_list = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]
    return ''.join(chr(int(b, 2)) for b in bytes_list)

#Binary to Gray Code
def binary_to_gray(binary_str):
    gray = ''
    gray += binary_str[0]  # MSB is same
    for i in range(1, len(binary_str)):
        gray += str(int(binary_str[i-1]) ^ int(binary_str[i]))
    return gray

#Gray Code to Binary
def gray_to_binary(gray_str):
    binary = ''
    binary += gray_str[0]  # MSB is same
    for i in range(1, len(gray_str)):
        binary += str(int(binary[i-1]) ^ int(gray_str[i]))
    return binary

if __name__ == "__main__":
    main()