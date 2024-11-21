from tkinter import filedialog
from encryption import encrypt, decrypt
from key_management import generate_rsa_keys, load_rsa_keys
import logging

def encrypt_file(password, passphrase):
    file_path = filedialog.askopenfilename()
    if not file_path:
        return None, "File encryption canceled."
    public_key, private_key = generate_rsa_keys()
    with open(file_path, "rb") as file:
        file_data = file.read()
    encrypted_data = encrypt(file_data.decode(), password, public_key)
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, "w") as file:
        file.write(str(encrypted_data))
    logging.info("File encrypted successfully.")
    return encrypted_file_path, "File encrypted successfully."

def decrypt_file(password, passphrase):
    file_path = filedialog.askopenfilename()
    if not file_path:
        return None, "File decryption canceled."
    private_key = load_rsa_keys({'encrypted_private_key': file_path}, passphrase)[0]
    with open(file_path, "r") as file:
        encrypted_data = eval(file.read())
    decrypted_text = decrypt(encrypted_data, password, private_key)
    decrypted_file_path = file_path.replace(".enc", "")
    with open(decrypted_file_path, "w") as file:
        file.write(decrypted_text)
    logging.info("File decrypted successfully.")
    return decrypted_file_path, "File decrypted successfully."