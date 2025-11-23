import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

#symmetric encryption
def aes_ed(massage):
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    aes = AESGCM(key)
    
    ciphertext = nonce + aes.encrypt(nonce, massage, None)
    plaintext = aes.decrypt(ciphertext[:12], ciphertext[12:], None)
    return key.hex(), ciphertext.hex(), plaintext.decode()

#asymmetric encryption
def rsa_ed(message):
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
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext.hex(), plaintext.decode()

if __name__ == "__main__":
    key, ciphertext, plaintext = aes_ed(b"Hello, AES!")
    print("AES-GCM Encryption")
    print("Key:", key)
    print("Ciphertext:", ciphertext)
    print("Plaintext:", plaintext)
    
    ciphertext, plaintext = rsa_ed("Hello, RSA!")
    print("\nRSA Encryption")
    print("Ciphertext:", ciphertext)
    print("Plaintext:", plaintext)
    