import logging

def configure_logging(level=logging.INFO, log_file="secure_app.log"):
    """Configure logging settings."""
    logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ])