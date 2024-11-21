import pyotp
import logging
from collections import defaultdict
import time

mfa_attempts = defaultdict(list)
MFA_ATTEMPT_WINDOW = 60  # Time window in seconds (1 minute)
MAX_MFA_ATTEMPTS = 3

def request_mfa_code() -> str:
    """Request a multi-factor authentication (MFA) code from the user."""
    return input("Enter MFA code: ")

def verify_mfa_code(mfa_code: str, secret: str) -> bool:
    """Verify the provided MFA code using Google Authenticator.
    
    Args:
        mfa_code (str): The MFA code to verify.
        secret (str): The secret key used to generate the MFA code.
    
    Returns:
        bool: True if the MFA code is valid, False otherwise.
    
    Raises:
        ValueError: If any input is invalid.
        Exception: If verification fails.
    """
    if not mfa_code or not secret:
        raise ValueError("Invalid input for verifying MFA code.")
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(mfa_code)
    except Exception as e:
        logging.error(f"Failed to verify MFA code: {e}")
        raise

def check_mfa_rate_limit():
    """Check if the MFA attempts exceed the rate limit.
    
    Raises:
        ValueError: If the rate limit is exceeded.
    """
    current_time = int(time.time())
    # Remove attempts outside the time window
    for timestamp in list(mfa_attempts.keys()):
        if current_time - timestamp >= MFA_ATTEMPT_WINDOW:
            del mfa_attempts[timestamp]
    attempts = mfa_attempts[current_time]
    if len(attempts) >= MAX_MFA_ATTEMPTS:
        logging.warning("Too many MFA attempts. Please try again later.")
        time.sleep(5)  # Delay to mitigate brute force attacks
        raise ValueError("Too many MFA attempts. Please try again later.")
    attempts.append(current_time)
    mfa_attempts[current_time] = [t for t in attempts if current_time - t < MFA_ATTEMPT_WINDOW]
    logging.info(f"MFA attempt recorded at {current_time}. Total attempts: {len(attempts)}")