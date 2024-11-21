import hvac
import os
import logging
import time

# Initialize HashiCorp Vault client
vault_addr = os.getenv('VAULT_ADDR')
vault_token = os.getenv('VAULT_TOKEN')

if not vault_addr or not vault_token:
    logging.error("Vault configuration environment variables not set.")
    raise EnvironmentError("Vault configuration environment variables not set.")

vault_client = hvac.Client(url=vault_addr)
vault_client.token = vault_token

# Set logging level
logging.basicConfig(level=logging.INFO)

def get_secret(path: str, key: str) -> str:
    """Retrieve a secret from HashiCorp Vault.
    
    Args:
        path (str): The path to the secret in Vault.
        key (str): The key of the secret to retrieve.
    
    Returns:
        str: The retrieved secret value.
    
    Raises:
        ValueError: If the path or key is invalid.
        Exception: If retrieving the secret fails.
    """
    if not isinstance(path, str) or not isinstance(key, str):
        logging.error("Path and key must be strings.")
        raise ValueError("Path and key must be strings.")
    
    retries = 3
    for attempt in range(retries):
        try:
            secret = vault_client.secrets.kv.v2.read_secret_version(path=path)['data']['data'][key]
            logging.info(f"Secret {path}/{key} retrieved successfully.")
            return secret
        except Exception as e:
            logging.error(f"Failed to retrieve secret {path}/{key} on attempt {attempt + 1}: {e}")
            if attempt < retries - 1:
                time.sleep(2 ** attempt)  # Exponential backoff
            else:
                raise