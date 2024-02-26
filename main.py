import warnings
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag
from cryptography.utils import CryptographyDeprecationWarning
from ChatAPI import askChatPassword
from mfa import addUserToMFA, isUserValid
import pickle
import os
import string
import random
import webbrowser
    
warnings.simplefilter("ignore", CryptographyDeprecationWarning)

# self.encryption_type
# 1 = AES,
# 2 = 3DES
# 3 = Blowfish

class PasswordManager:
    def __init__(self):
        self.__master_password = None
        self.list_of_service_names = []
        self.usernames_and_passwords = {}
        self.key_file = "key.bin"
        self.encryption_type = None

    # Method for key derivation using PBKDF2HMAC
    def key_derivation(self, password, salt):
        if self.encryption_type == 1: # AES
            # Use PBKDF2HMAC with SHA256, the provided salt, and other parameters
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),  # SHA-256 hash algorithm
                salt=salt,
                iterations=100000,  # times the hash function is applied to the input data
                length=32,  # Ensure the key length is 32 bytes (256 bits)
                backend=default_backend()
            )
        elif self.encryption_type == 2:  # 3DES
            # Use PBKDF2HMAC with SHA256, the provided salt, and other parameters
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),  # SHA-256 hash algorithm
                salt=salt,
                iterations=100000,  # times the hash function is applied to the input data
                length=24,  # Ensure the key length is 24 bytes (192 bits) for 3DES
                backend=default_backend()
            )
        elif self.encryption_type == 3:
            # Blowfish key derivation
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),  # SHA-256 hash algorithm
                salt=salt,
                iterations=100000,  # times the hash function is applied to the input data
                length=32,  # Ensure the key length is 32 bytes (256 bits) for Blowfish
                backend=default_backend()
            )
        else:
            raise ValueError("Invalid encryption type")
        # Derive the key from the password and return it
        key = kdf.derive(password.encode())
        return key

    # Method to generate and save key to a file
    def generate_and_save_key(self):
        # Check if the key file doesn't exist
        if not os.path.exists(self.key_file):
            # Generate a random 128-bit salt
            salt = os.urandom(16)  # 128-bit salt
            # Derive the key using the master password and salt
            key = self.key_derivation(self.__master_password, salt)
            # Write the salt and key to the key file
            with open(self.key_file, 'wb') as key_file:
                key_file.write(salt + key)

    # Method to load key from a file
    def load_key(self):
        # Read the salt and key from the key file
        with open(self.key_file, 'rb') as key_file:
            data = key_file.read()
            salt = data[:16]
            # Derive the key using the master password and salt
            key = self.key_derivation(self.__master_password, salt)
        return key

    # Method to encrypt data using AES-GCM or 3DES-CFB
    def encrypt_data(self, data, key):
        if self.encryption_type == 1:
            # AES encryption with a 256-bit key
            iv = os.urandom(16)  # 128-bit IV for AES
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            tag = encryptor.tag
            return iv, tag, ciphertext
        elif self.encryption_type == 2:
            # 3DES encryption with a 192-bit key
            iv = os.urandom(8)  # 64-bit IV for 3DES
            cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            return iv, ciphertext
        elif self.encryption_type == 3:
            # Blowfish encryption
            iv = os.urandom(8)  # 64-bit IV for Blowfish
            cipher = Cipher(algorithms.Blowfish(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            return iv, ciphertext
        else:
            raise ValueError("Failed to encrypt the data")


    # Method to decrypt data using AES-GCM or 3DES-CFB
    def decrypt_data(self, encrypted_data, key):
        if self.encryption_type == 1:
            iv, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
            # AES decryption with a 256-bit key
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        elif self.encryption_type == 2:
            iv, ciphertext = encrypted_data[:8], encrypted_data[8:]
            # 3DES decryption with a 192-bit key
            cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend())
        elif self.encryption_type == 3:
            # Blowfish decryption
            iv, ciphertext = encrypted_data[:8], encrypted_data[8:]
            cipher = Cipher(algorithms.Blowfish(key), modes.CFB(iv), backend=default_backend())
        else:
            raise ValueError("Invalid encryption type")

        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_data

    # Method to save encrypted data to a file
    def save_to_file(self, filename):
        # Generate and save the key if it doesn't exist
        self.generate_and_save_key()
        # Load the key
        key = self.load_key()
        # Encrypt the pickled instance using the key and save to the file

        if self.encryption_type == 1:
            iv, tag, encrypted_data = self.encrypt_data(pickle.dumps(self), key)
            with open(filename, 'wb') as outp:
                outp.write(iv + tag + encrypted_data)
        elif self.encryption_type == 2: 
            iv, encrypted_data = self.encrypt_data(pickle.dumps(self), key)
            with open(filename, 'wb') as outp:
                outp.write(iv + encrypted_data)
        elif self.encryption_type == 3: 
            iv, encrypted_data = self.encrypt_data(pickle.dumps(self), key)
            with open(filename, 'wb') as outp:
                outp.write(iv + encrypted_data)
        else:
            raise ValueError("Could not save to file")

    # Method to load encrypted data from a file
    def load_from_file(self, filename):
        with open("flag.txt", 'r') as file:
            self.encryption_type = file.read()
            self.encryption_type = int(self.encryption_type)

        try:
            # Open the file in binary read mode
            with open(filename, 'rb') as file:
                # Read the entire content of the file
                data = file.read()
                # Extract IV, tag, and encrypted data from the file content

                if self.encryption_type == 1:
                    iv = data[:16]
                    tag = data[16:32]
                    encrypted_data = data[32:]
                elif self.encryption_type == 2:
                    iv = data[:16]
                    encrypted_data = data[16:]
                elif self.encryption_type == 3:
                    iv = data[:16]
                    encrypted_data = data[16:]
                else:
                    raise ValueError("Could not get data from ", filename)
                
                # Create an instance of PasswordManager
                pm = PasswordManager()

                with open("flag.txt", 'r') as file:
                    pm.encryption_type = file.read()
                    pm.encryption_type = int(pm.encryption_type)

                # Prompt the user for the master password
                pm.__master_password = str(input("Enter your master password: "))
                # Load the key associated with the master password
                key = pm.load_key()

                try:
                    if pm.encryption_type == 1:
                        # Attempt to decrypt the data using AES-GCM
                        decrypted_data = pm.decrypt_data(iv + tag + encrypted_data, key)
                        # Unpickle and return the decrypted data
                        return pickle.loads(decrypted_data)
                    elif pm.encryption_type == 2:
                        # Attempt to decrypt the data using 3DES
                        decrypted_data = pm.decrypt_data(iv + encrypted_data, key)
                        # Unpickle and return the decrypted data
                        return pickle.loads(decrypted_data)
                    elif pm.encryption_type == 3:
                        # Attempt to decrypt the data using Blowfish
                        decrypted_data = pm.decrypt_data(iv + encrypted_data, key)
                        # Unpickle and return the decrypted data
                        return pickle.loads(decrypted_data)     
                                          
                except InvalidTag:  # Catch the InvalidTag exception
                    # Display an error message for an invalid authentication tag
                    print("Invalid authentication tag. Incorrect master password or file corruption.")
                    return None
                
                except pickle.UnpicklingError:
                    # Display an error message for an invalid load key
                    print(f"Failed to unpickle data. Incorrect master password.")
                    return None
                
                except OverflowError:
                    print(f"Failed to unpickle data. Incorrect master password.")
                    return None

        except FileNotFoundError:
            # Handle the case where the file is not found
            print("File not found")
            return None
        
    def create_master_password(self):
        user_input = str(input("Please create a master password: "))
        user_input_repeat = str(input("Please re enter your master password (passwords must match): "))
        if user_input == user_input_repeat:
            addUserToMFA("")
            print("Passwords match! \nLogging in...\n")
            self.__master_password = user_input
        else:
            print("Passwords don't match! Please try again.")
            self.create_master_password()
    
    def login(self):
        passcode = str(input("Enter passcode from authenticator app: "))
        msg = ''
        if isUserValid(passcode):
            print("Successfully logged in.")
        else:
            msg = 'Invalid passcode! Please try again.'
        
        if msg:
            print(msg)
            self.login()

    def generate_random_password(self):
        #TODO to by done by Michael Youssef
        characters = string.ascii_letters + string.digits
        random_string = ''.join(random.choice(characters) for _ in range(16))
        print("Your random password is: " + random_string)

    def add_login(self):
        temp_service_name = input("What is the name of the service this login is for?: ")
        temp_username = input("What is the username?: ")
        temp_password = input("What is the password?: ")
        self.list_of_service_names.append(temp_service_name)
        self.usernames_and_passwords[temp_username] = temp_password
        print("Login added!")

    def delete_login(self):
        #TODO to by done by Michael Youssef
        self.print_all_saved_logins()
        login_to_delete = int(input(f"Of the {len(self.list_of_service_names)} saved logins, which would you like to delete? (Enter a number): "))
        login_to_delete -= 1
        del self.list_of_service_names[login_to_delete]
        keys = list(self.usernames_and_passwords.keys())
        del self.usernames_and_passwords[keys[login_to_delete]]
        self.print_all_saved_logins()
        print("Login has successfully been deleted.")

    def print_all_saved_logins(self):
        #TODO to by done by Michael Youssef
        iterator = 0
        print("======================================")
        for key, value in self.usernames_and_passwords.items():
            print("Service: " + str(self.list_of_service_names[iterator]))
            print(f"Username: {key}, Password: {value}")
            print("======================================")
            iterator += 1

    def ask_ai(self):
        #TODO to by done by June Galindo
        text_to_check = input("Enter the password you want to check: ")
        # Check if the entered text is the master password
        if text_to_check == self.__master_password:
            print("Master password detected. Skipping ChatGPT API request.")
            return
        print("Processing...")
        askChatPassword(text_to_check)

    def quit_password_manager(self, __filename):
        print("Goodbye.")
        # Set the encryption type to either AES or 3DES
        self.encryption_type = random.choice([1, 2, 3])
        # Print Algorithm
        if self.encryption_type == 1:
            print('Using AES')
        elif self.encryption_type == 2:
            print('Using 3DES')
        elif self.encryption_type == 3:
            print('Using Blowfish')
        else:
            print('')
        # Write the encryption type to a file
        with open("flag.txt", 'w') as file:
            file.write(str(self.encryption_type))
        self.save_to_file(__filename)
    
    def learn_more(self):
        url = "https://olucdenver-my.sharepoint.com/:p:/g/personal/brandon_borgonah_ucdenver_edu/EWTk8JmVAkhJnCjZOnl-43QBUVBlV4pCJtnnAsdWymJd-w?e=phbOVR"
        print("You are being redirected to a webpage where you can learn more. If you are not automatically redirected, please use this link:")
        print(str(url) + "\n")
        webbrowser.open(url)

def main():
    __filename = "passwords.txt" #TODO CHANGE THIS FILENAME AS NEEDED!!!
    flag_filename = "flag.txt"
    pm = PasswordManager()

    if os.path.exists(__filename) and os.path.exists(flag_filename):
        # File exists, load from file, login
        pm = pm.load_from_file(__filename)
        if pm is None:
            print("Failed to load PasswordManager instance. Exiting.")
            return
        pm.login()
    else:
        # File does not exist, create login
        pm.create_master_password()

    print("Welcome to password manager. ", end="")
    while True:
        print("Please select from one of the following options: \n" +
            "1. Generate a random password\n" + 
            "2. Add a login username and password\n" +
            "3. Delete a login username and password\n" +
            "4. Review all saved login usernames and passwords\n" +
            "5. Ask an AI if your password is strong enough\n" +
            "6. Save and exit\n" + 
            "7. Learn more\n")
        user_option = int(input())
        if user_option == 1:
            pm.generate_random_password()
        elif user_option == 2:
            pm.add_login()
        elif user_option == 3:
            pm.delete_login()
        elif user_option == 4:
            pm.print_all_saved_logins()
        elif user_option == 5:
            pm.ask_ai()
        elif user_option == 6:
            pm.quit_password_manager(__filename)
            return None
        elif user_option == 7:
            pm.learn_more()
        else:
            print("Invalid option. Please choose a number between 1 and 7.")
    
main()