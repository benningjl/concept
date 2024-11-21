from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
import base64
import uuid
import time
import logging
from key_management import decrypt_with_rsa  # Change to absolute import

SALT_SIZE = 16
KEY_SIZE = 32
IV_SIZE = 16
VERSION = 1

def secure_random_bytes(size: int) -> bytes:
    """Generate secure random bytes."""
    return get_random_bytes(size)

def encrypt(data: str, password: str, public_key: bytes) -> dict:
    """Encrypt data using AES-GCM with HMAC, RSA-protected keys, and a nonce.
    
    Args:
        data (str): The plaintext data to encrypt.
        password (str): The password used to derive the AES key.
        public_key (bytes): The RSA public key used to encrypt the AES key.
    
    Returns:
        dict: A dictionary containing the encrypted data and associated metadata.
    
    Raises:
        ValueError: If any input is invalid.
        Exception: If encryption fails.
    """
    if not data or not password or not public_key:
        raise ValueError("Invalid input for encryption.")
    try:
        salt = secure_random_bytes(SALT_SIZE)
        aes_key = generate_aes_key(password, salt)
        encrypted_aes_key = encrypt_with_rsa(public_key, aes_key)
        nonce = secure_random_bytes(IV_SIZE)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)

        # Encrypt the data
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())

        # Generate HMAC for integrity verification
        hmac = HMAC.new(aes_key, ciphertext, SHA256).digest()

        # Add timestamp
        timestamp = int(time.time())

        # Add unique identifier
        unique_id = str(uuid.uuid4())

        logging.info(f"Data encrypted with unique ID: {unique_id} at timestamp: {timestamp}")

        return {
            'version': VERSION,
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'salt': base64.b64encode(salt).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'tag': base64.b64encode(tag).decode(),
            'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode(),
            'hmac': base64.b64encode(hmac).decode(),
            'timestamp': timestamp,
            'unique_id': unique_id,
            'key_rotation_timestamp': timestamp
        }
    except Exception as e:
        logging.error(f"Encryption failed: {e}")
        raise

def decrypt(encrypted: dict, password: str, private_key: bytes) -> str:
    """Decrypt data using AES-GCM with HMAC verification and RSA-protected keys.
    
    Args:
        encrypted (dict): The dictionary containing the encrypted data and associated metadata.
        password (str): The password used to derive the AES key.
        private_key (bytes): The RSA private key used to decrypt the AES key.
    
    Returns:
        str: The decrypted plaintext data.
    
    Raises:
        ValueError: If any input is invalid or HMAC verification fails.
        Exception: If decryption fails.
    """
    if not encrypted or not password or not private_key:
        raise ValueError("Invalid input for decryption.")
    try:
        verify_encrypted_data_structure(encrypted)

        salt = base64.b64decode(encrypted['salt'])
        nonce = base64.b64decode(encrypted['nonce'])
        ciphertext = base64.b64decode(encrypted['ciphertext'])
        tag = base64.b64decode(encrypted['tag'])
        encrypted_aes_key = base64.b64decode(encrypted['encrypted_aes_key'])
        hmac = base64.b64decode(encrypted['hmac'])

        aes_key = decrypt_with_rsa(private_key, encrypted_aes_key)

        # Verify HMAC for integrity
        if HMAC.new(aes_key, ciphertext, SHA256).digest() != hmac:
            raise ValueError("HMAC verification failed. Data integrity compromised.")

        # Decrypt data
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

        logging.info(f"Data decrypted with unique ID: {encrypted['unique_id']} at timestamp: {encrypted['timestamp']}")

        return decrypted_data.decode()
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        raise