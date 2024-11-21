import os
import tkinter as tk
from tkinter import messagebox, Menu
from config import get_secret
from encryption import encrypt, decrypt
from key_management import generate_rsa_keys, store_rsa_keys, load_rsa_keys, rotate_rsa_keys_if_needed
from mfa import request_mfa_code, verify_mfa_code, check_mfa_rate_limit
from backup_utils import secure_backup
from logging_config import configure_logging
from error_handling import handle_error, validate_input
from user_authentication import hash_password, verify_password
from file_operations import encrypt_file, decrypt_file
from progress import ProgressIndicator
from tooltips import ToolTip
from config_management import load_config, get_config_value
import logging

# Set environment variables programmatically
os.environ['VAULT_ADDR'] = 'http://your-vault-address'
os.environ['VAULT_TOKEN'] = 'your-vault-token'

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption App")

        # Load configuration
        self.config = load_config()

        # Configure logging
        log_level = get_config_value(self.config, 'Logging', 'level')
        log_file = get_config_value(self.config, 'Logging', 'file')
        configure_logging(level=log_level, log_file=log_file)

        # Create menu bar
        self.menu_bar = Menu(root)
        root.config(menu=self.menu_bar)

        # Add Help menu
        self.help_menu = Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Help", menu=self.help_menu)
        self.help_menu.add_command(label="Instructions", command=self.show_instructions)
        self.help_menu.add_command(label="About", command=self.show_about)

        # Create frames
        self.input_frame = tk.Frame(root)
        self.input_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        self.button_frame = tk.Frame(root)
        self.button_frame.grid(row=1, column=0, padx=10, pady=10, sticky="ew")
        self.output_frame = tk.Frame(root)
        self.output_frame.grid(row=2, column=0, padx=10, pady=10, sticky="ew")
        self.status_frame = tk.Frame(root)
        self.status_frame.grid(row=3, column=0, padx=10, pady=10, sticky="ew")

        # MFA Code
        self.mfa_code_label = tk.Label(self.input_frame, text="MFA Code:")
        self.mfa_code_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.mfa_code_entry = tk.Entry(self.input_frame)
        self.mfa_code_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        ToolTip(self.mfa_code_entry, "Enter the MFA code provided by your authenticator app.")

        # Encryption Password
        self.password_label = tk.Label(self.input_frame, text="Encryption Password:")
        self.password_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.password_entry = tk.Entry(self.input_frame, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        ToolTip(self.password_entry, "Enter the encryption password.")

        # RSA Passphrase
        self.passphrase_label = tk.Label(self.input_frame, text="RSA Passphrase:")
        self.passphrase_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.passphrase_entry = tk.Entry(self.input_frame, show="*")
        self.passphrase_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        ToolTip(self.passphrase_entry, "Enter the RSA passphrase.")

        # Backup URL
        self.backup_url_label = tk.Label(self.input_frame, text="Backup URL:")
        self.backup_url_label.grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.backup_url_entry = tk.Entry(self.input_frame)
        self.backup_url_entry.grid(row=3, column=1, padx=5, pady=5, sticky="ew")
        ToolTip(self.backup_url_entry, "Enter the backup URL where encrypted data will be stored.")

        # Plaintext
        self.plaintext_label = tk.Label(self.input_frame, text="Plaintext:")
        self.plaintext_label.grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.plaintext_entry = tk.Entry(self.input_frame)
        self.plaintext_entry.grid(row=4, column=1, padx=5, pady=5, sticky="ew")
        ToolTip(self.plaintext_entry, "Enter the plaintext message you want to encrypt.")

        # Buttons
        self.generate_keys_button = tk.Button(self.button_frame, text="Generate RSA Keys", command=self.generate_rsa_keys)
        self.generate_keys_button.grid(row=0, column=0, padx=5, pady=5)
        ToolTip(self.generate_keys_button, "Generate new RSA keys.")

        self.encrypt_button = tk.Button(self.button_frame, text="Encrypt", command=self.encrypt_data)
        self.encrypt_button.grid(row=0, column=1, padx=5, pady=5)
        ToolTip(self.encrypt_button, "Encrypt the plaintext message.")

        self.decrypt_button = tk.Button(self.button_frame, text="Decrypt", command=self.decrypt_data)
        self.decrypt_button.grid(row=0, column=2, padx=5, pady=5)
        ToolTip(self.decrypt_button, "Decrypt the encrypted message.")

        self.backup_button = tk.Button(self.button_frame, text="Backup", command=self.backup_data)
        self.backup_button.grid(row=0, column=3, padx=5, pady=5)
        ToolTip(self.backup_button, "Securely backup the encrypted data.")

        self.clear_button = tk.Button(self.button_frame, text="Clear", command=self.clear_output)
        self.clear_button.grid(row=0, column=4, padx=5, pady=5)
        ToolTip(self.clear_button, "Clear the output text area.")

        self.encrypt_file_button = tk.Button(self.button_frame, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_file_button.grid(row=1, column=0, padx=5, pady=5)
        ToolTip(self.encrypt_file_button, "Encrypt a file.")

        self.decrypt_file_button = tk.Button(self.button_frame, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_file_button.grid(row=1, column=1, padx=5, pady=5)
        ToolTip(self.decrypt_file_button, "Decrypt a file.")

        # Output
        self.output_text = tk.Text(self.output_frame, height=10, width=80)
        self.output_text.grid(row=0, column=0, padx=5, pady=5)
        ToolTip(self.output_text, "Output of the operations will be displayed here.")

        # Instructions
        self.instructions_text = tk.Text(self.output_frame, height=10, width=80, wrap=tk.WORD)
        self.instructions_text.grid(row=1, column=0, padx=5, pady=5)
        self.instructions_text.insert(tk.END, self.get_instructions())
        self.instructions_text.config(state=tk.DISABLED)

        # Status Bar
        self.status_var = tk.StringVar()
        self.status_bar = tk.Label(self.status_frame, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        self.update_status("Ready")

        # Progress Bar
        self.progress_indicator = ProgressIndicator(self.status_frame)

    def update_status(self, message):
        self.status_var.set(message)
        self.root.update_idletasks()

    def generate_rsa_keys(self):
        try:
            self.update_status("Generating RSA keys...")
            self.progress_indicator.update_progress(0)
            public_key, private_key = generate_rsa_keys()
            self.output_text.insert(tk.END, "RSA keys generated.\n")
            logging.info("RSA keys generated.")
            self.update_status("RSA keys generated.")
            self.progress_indicator.update_progress(100)
        except Exception as e:
            handle_error("Failed to generate RSA keys", e)
            self.update_status("Failed to generate RSA keys.")
            self.progress_indicator.update_progress(0)

    def encrypt_data(self):
        try:
            self.update_status("Encrypting data...")
            self.progress_indicator.update_progress(0)
            password = self.password_entry.get()
            passphrase = self.passphrase_entry.get()
            plaintext = self.plaintext_entry.get()
            validate_input(password, "Encryption Password")
            validate_input(passphrase, "RSA Passphrase")
            validate_input(plaintext, "Plaintext")
            public_key, private_key = generate_rsa_keys()
            encrypted_data = encrypt(plaintext, password, public_key)
            self.output_text.insert(tk.END, f"Encrypted Data: {encrypted_data}\n")
            logging.info("Data encrypted successfully.")
            self.update_status("Data encrypted successfully.")
            self.progress_indicator.update_progress(100)
        except Exception as e:
            handle_error("Failed to encrypt data", e)
            self.update_status("Failed to encrypt data.")
            self.progress_indicator.update_progress(0)

    def decrypt_data(self):
        try:
            self.update_status("Decrypting data...")
            self.progress_indicator.update_progress(0)
            password = self.password_entry.get()
            passphrase = self.passphrase_entry.get()
            encrypted_data = self.output_text.get("1.0", tk.END).strip()
            validate_input(password, "Encryption Password")
            validate_input(passphrase, "RSA Passphrase")
            validate_input(encrypted_data, "Encrypted Data")
            private_key = load_rsa_keys({'encrypted_private_key': encrypted_data}, passphrase)[0]
            decrypted_text = decrypt(encrypted_data, password, private_key)
            self.output_text.insert(tk.END, f"Decrypted Text: {decrypted_text}\n")
            logging.info("Data decrypted successfully.")
            self.update_status("Data decrypted successfully.")
            self.progress_indicator.update_progress(100)
        except Exception as e:
            handle_error("Failed to decrypt data", e)
            self.update_status("Failed to decrypt data.")
            self.progress_indicator.update_progress(0)

    def backup_data(self):
        try:
            self.update_status("Backing up data...")
            self.progress_indicator.update_progress(0)
            backup_url = self.backup_url_entry.get()
            encrypted_data = self.output_text.get("1.0", tk.END).strip()
            validate_input(backup_url, "Backup URL")
            validate_input(encrypted_data, "Encrypted Data")
            secure_backup(encrypted_data, backup_url)
            self.output_text.insert(tk.END, "Data securely backed up.\n")
            logging.info("Data securely backed up.")
            self.update_status("Data securely backed up.")
            self.progress_indicator.update_progress(100)
        except Exception as e:
            handle_error("Failed to backup data", e)
            self.update_status("Failed to backup data.")
            self.progress_indicator.update_progress(0)

    def clear_output(self):
        self.output_text.delete("1.0", tk.END)
        self.update_status("Output cleared.")

    def encrypt_file(self):
        try:
            self.update_status("Encrypting file...")
            self.progress_indicator.update_progress(0)
            password = self.password_entry.get()
            passphrase = self.passphrase_entry.get()
            validate_input(password, "Encryption Password")
            validate_input(passphrase, "RSA Passphrase")
            encrypted_file_path, status_message = encrypt_file(password, passphrase)
            if encrypted_file_path:
                self.output_text.insert(tk.END, f"File encrypted: {encrypted_file_path}\n")
            self.update_status(status_message)
            self.progress_indicator.update_progress(100)
        except Exception as e:
            handle_error("Failed to encrypt file", e)
            self.update_status("Failed to encrypt file.")
            self.progress_indicator.update_progress(0)

    def decrypt_file(self):
        try:
            self.update_status("Decrypting file...")
            self.progress_indicator.update_progress(0)
            password = self.password_entry.get()
            passphrase = self.passphrase_entry.get()
            validate_input(password, "Encryption Password")
            validate_input(passphrase, "RSA Passphrase")
            decrypted_file_path, status_message = decrypt_file(password, passphrase)
            if decrypted_file_path:
                self.output_text.insert(tk.END, f"File decrypted: {decrypted_file_path}\n")
            self.update_status(status_message)
            self.progress_indicator.update_progress(100)
        except Exception as e:
            handle_error("Failed to decrypt file", e)
            self.update_status("Failed to decrypt file.")
            self.progress_indicator.update_progress(0)

    def show_instructions(self):
        instructions = self.get_instructions()
        messagebox.showinfo("Instructions", instructions)

    def show_about(self):
        about_message = "Encryption App v1.0\nDeveloped by Your Name\nFor more information, visit: https://yourwebsite.com"
        messagebox.showinfo("About", about_message)

    def get_instructions(self):
        instructions = (
            "Welcome to the Encryption App!\n\n"
            "Instructions:\n"
            "1. Enter the MFA code provided by your authenticator app.\n"
            "2. Enter the encryption password and RSA passphrase.\n"
            "3. Enter the backup URL where encrypted data will be stored.\n"
            "4. Enter the plaintext message you want to encrypt.\n"
            "5. Use the 'Generate RSA Keys' button to generate new RSA keys.\n"
            "6. Use the 'Encrypt' button to encrypt the plaintext message.\n"
            "7. Use the 'Decrypt' button to decrypt the encrypted message.\n"
            "8. Use the 'Backup' button to securely backup the encrypted data.\n"
            "9. Use the 'Encrypt File' button to encrypt a file.\n"
            "10. Use the 'Decrypt File' button to decrypt a file.\n\n"
            "For more information, refer to the Help menu."
        )
        return instructions

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = EncryptionApp(root)
        root.mainloop()
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        messagebox.showerror("Error", f"An error occurred: {e}")
