import requests
import logging

def secure_backup(data: dict, backup_url: str):
    """Securely backup encrypted data to a remote server.
    
    Args:
        data (dict): The encrypted data to backup.
        backup_url (str): The URL of the remote server to backup the data to.
    
    Raises:
        ValueError: If the backup URL is invalid.
        Exception: If the backup fails.
    """
    if not backup_url.startswith("https://"):
        raise ValueError("Backup URL must use HTTPS.")
    try:
        response = requests.post(backup_url, json=data)
        response.raise_for_status()
        logging.info("Data securely backed up.")
    except requests.RequestException as e:
        logging.error(f"Failed to backup data: {e}")
        raise