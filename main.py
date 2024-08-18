import os
import hmac
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes


# Key generation using Argon2 from argon2-cffi
def generate_key(passphrase: str, salt: bytes = None) -> bytes:
    if salt is None:
        salt = os.urandom(16)  # Generate a new salt

    ph = PasswordHasher(time_cost=2, memory_cost=102400, parallelism=8)
    key = ph.hash(passphrase.encode() + salt)
    key = key.encode()[:32]  # Truncate or expand to 32 bytes (256 bits)
    return key, salt


# Padding
def pad_message(message: bytes) -> bytes:
    padder = PKCS7(128).padder()
    padded_message = padder.update(message) + padder.finalize()
    return padded_message


# Message Authentication Code (MAC)
def generate_mac(key: bytes, message: bytes) -> bytes:
    mac = HMAC(key, hashes.SHA256(), backend=default_backend())
    mac.update(message)
    return mac.finalize()


# Encryption
def encrypt_message(key: bytes, plaintext: bytes, associated_data: bytes = None) -> bytes:
    iv = os.urandom(12)  # 96-bit IV for GCM
    encryptor = Cipher(
        algorithms.AES(key), modes.GCM(iv), backend=default_backend()
    ).encryptor()

    if associated_data:
        encryptor.authenticate_additional_data(associated_data)

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext + encryptor.tag


# Decryption
def decrypt_message(key: bytes, ciphertext: bytes, associated_data: bytes = None) -> bytes:
    iv = ciphertext[:12]
    tag = ciphertext[-16:]
    encrypted_message = ciphertext[12:-16]

    decryptor = Cipher(
        algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()
    ).decryptor()

    if associated_data:
        decryptor.authenticate_additional_data(associated_data)

    plaintext = decryptor.update(encrypted_message) + decryptor.finalize()
    return plaintext


# Full encryption process
def encrypt_with_mac(passphrase: str, message: str, associated_data: bytes = None) -> bytes:
    key, salt = generate_key(passphrase)
    padded_message = pad_message(message.encode())
    mac = generate_mac(key, padded_message)
    ciphertext = encrypt_message(key, padded_message + mac, associated_data)
    return salt + ciphertext


# Full decryption process
def decrypt_with_mac(passphrase: str, ciphertext: bytes, associated_data: bytes = None) -> str:
    salt = ciphertext[:16]
    encrypted_message = ciphertext[16:]
    key, _ = generate_key(passphrase, salt)

    decrypted_padded_message = decrypt_message(key, encrypted_message, associated_data)
    message, received_mac = decrypted_padded_message[:-32], decrypted_padded_message[-32:]

    expected_mac = generate_mac(key, message)
    if not hmac.compare_digest(received_mac, expected_mac):
        raise ValueError("Invalid MAC. Message has been tampered with!")

    return message.rstrip(b'\x00').decode('utf-8')


# Example usage
if __name__ == "__main__":
    passphrase = "strongpassword"
    message = "This is a secret message."
    associated_data = b"header information"

    encrypted_message = encrypt_with_mac(passphrase, message, associated_data)
    print(f"Encrypted message: {encrypted_message.hex()}")

    decrypted_message = decrypt_with_mac(passphrase, encrypted_message, associated_data)
    print(f"Decrypted message: {decrypted_message}")
