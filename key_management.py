from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import logging
import time

RSA_KEY_SIZE = 2048

def generate_rsa_keys() -> (bytes, bytes):
    """Generate RSA public and private keys."""
    key = RSA.generate(RSA_KEY_SIZE)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    logging.info("RSA keys generated.")
    return public_key, private_key

def store_rsa_keys(private_key: bytes, public_key: bytes, passphrase: str) -> dict:
    """Encrypt and store RSA keys securely.
    
    Args:
        private_key (bytes): The RSA private key to store.
        public_key (bytes): The RSA public key to store.
        passphrase (str): The passphrase used to encrypt the private key.
    
    Returns:
        dict: A dictionary containing the encrypted private key, public key, and key rotation timestamp.
    
    Raises:
        ValueError: If any input is invalid.
        Exception: If storing the keys fails.
    """
    if not private_key or not public_key or not passphrase:
        raise ValueError("Invalid input for storing RSA keys.")
    try:
        encrypted_private_key = RSA.import_key(private_key).export_key(passphrase=passphrase, pkcs=8, protection="scryptAndAES128-CBC")
        logging.info("RSA keys stored securely.")
        return {
            'encrypted_private_key': base64.b64encode(encrypted_private_key).decode(),
            'public_key': base64.b64encode(public_key).decode(),
            'key_rotation_timestamp': int(time.time())
        }
    except Exception as e:
        logging.error(f"Failed to store RSA keys: {e}")
        raise

def load_rsa_keys(stored_keys: dict, passphrase: str) -> (bytes, bytes):
    """Load and decrypt RSA keys.
    
    Args:
        stored_keys (dict): The dictionary containing the encrypted private key and public key.
        passphrase (str): The passphrase used to decrypt the private key.
    
    Returns:
        tuple: A tuple containing the decrypted private key and public key.
    
    Raises:
        ValueError: If any input is invalid.
        Exception: If loading the keys fails.
    """
    if not stored_keys or not passphrase:
        raise ValueError("Invalid input for loading RSA keys.")
    try:
        encrypted_private_key = base64.b64decode(stored_keys['encrypted_private_key'])
        public_key = base64.b64decode(stored_keys['public_key'])
        private_key = RSA.import_key(encrypted_private_key, passphrase=passphrase)
        logging.info("RSA keys loaded successfully.")
        logging.info(f"Key rotation timestamp: {stored_keys.get('key_rotation_timestamp', 'N/A')}")
        return private_key.export_key(), public_key
    except Exception as e:
        logging.error(f"Failed to load RSA keys: {e}")
        raise

def encrypt_with_rsa(public_key: bytes, aes_key: bytes) -> bytes:
    """Encrypt AES key with RSA."""
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.encrypt(aes_key)

def decrypt_with_rsa(private_key: bytes, encrypted_aes_key: bytes) -> bytes:
    """Decrypt AES key with RSA."""
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(encrypted_aes_key)

def rotate_rsa_keys_if_needed(passphrase: str) -> (bytes, bytes):
    """Rotate RSA keys if needed based on a condition."""
    # Example condition: Rotate keys every 30 days
    current_time = int(time.time())
    key_rotation_interval = 30 * 24 * 60 * 60  # 30 days in seconds
    last_rotation_time = get_last_rotation_time()  # Implement this function to retrieve the last rotation time

    if current_time - last_rotation_time >= key_rotation_interval:
        logging.info("Rotating RSA keys.")
        return generate_rsa_keys()
    else:
        logging.info("RSA key rotation not needed.")
        return None, None

def get_last_rotation_time() -> int:
    """Retrieve the last key rotation time. Implement this function as needed."""
    # Placeholder implementation
    return int(time.time()) - (31 * 24 * 60 * 60)  # Assume last rotation was 31 days ago