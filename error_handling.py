import logging

def handle_error(message: str, exception: Exception):
    """Handle errors by logging and raising an exception."""
    logging.error(f"{message}: {exception}")
    raise exception

def validate_input(input_value, input_name: str):
    """Validate input and raise ValueError if invalid."""
    if not input_value:
        raise ValueError(f"Invalid input for {input_name}.")