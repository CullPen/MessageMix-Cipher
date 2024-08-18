# MessageMix Cipher

MessageMix Cipher is a Python-based encryption tool that securely encrypts and decrypts messages using a combination of advanced cryptographic techniques. The tool utilizes Argon2 for key derivation, AES-GCM for encryption, and HMAC-SHA256 for message integrity.

## Features

- **Key Derivation with Argon2**: Uses Argon2, a memory-hard key derivation function, to generate a strong 256-bit encryption key from a user-provided passphrase.
- **AES-GCM Encryption**: Leverages AES in Galois/Counter Mode (GCM) for secure encryption and message authentication.
- **PKCS#7 Padding**: Ensures that the message length is a multiple of 128 bits.
- **HMAC-SHA256**: Provides message integrity by generating a Message Authentication Code (MAC) for the original message.
- **Salt and IV Generation**: Generates unique salts and initialization vectors (IVs) to enhance security and prevent rainbow table attacks.

## Installation

To run this project, you'll need to install the required dependencies:

1. Clone this repository:
    ```bash
    git clone https://github.com/yourusername/MessageMix-Cipher.git
    cd MessageMix-Cipher
    ```

2. Create a virtual environment (optional but recommended):
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. Install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```

### Required Packages

- `cryptography`: Provides cryptographic recipes and primitives to Python developers.
- `argon2-cffi`: Python bindings for the Argon2 password hashing function.

You can install these packages manually using pip:

```bash
pip install cryptography argon2-cffi
Usage

Here's a basic example of how to use the MessageMix Cipher:
from main import encrypt_with_mac, decrypt_with_mac

# Define passphrase, message, and optional associated data
passphrase = "strongpassword"
message = "This is a secret message."
associated_data = b"header information"

# Encrypt the message
encrypted_message = encrypt_with_mac(passphrase, message, associated_data)
print(f"Encrypted message: {encrypted_message.hex()}")

# Decrypt the message
decrypted_message = decrypt_with_mac(passphrase, encrypted_message, associated_data)
print(f"Decrypted message: {decrypted_message}")

Usage

Here's a basic example of how to use the MessageMix Cipher:
from main import encrypt_with_mac, decrypt_with_mac

# Define passphrase, message, and optional associated data
passphrase = "strongpassword"
message = "This is a secret message."
associated_data = b"header information"

# Encrypt the message
encrypted_message = encrypt_with_mac(passphrase, message, associated_data)
print(f"Encrypted message: {encrypted_message.hex()}")

# Decrypt the message
decrypted_message = decrypt_with_mac(passphrase, encrypted_message, associated_data)
print(f"Decrypted message: {decrypted_message}")
Encrypting a Message
The encrypt_with_mac function takes a passphrase, a message, and optional associated data as input.
It returns the encrypted message as a byte string, which includes the salt, IV, ciphertext, and MAC.
Decrypting a Message
The decrypt_with_mac function takes the passphrase and the encrypted message as input.
It returns the original decrypted message as a string, verifying the integrity of the message using the MAC.
Security Considerations

Passphrase Strength: The security of the encryption depends significantly on the strength of the passphrase. Use a strong, unique passphrase.
Key Management: Ensure that the passphrase and the generated key are securely managed and never exposed.
IV and Salt: The implementation generates a unique IV and salt for each encryption, which enhances security by preventing replay attacks and rainbow table attacks.
License

This project is licensed under the MIT License. See the LICENSE file for more details.

Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.
