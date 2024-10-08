import os
import random
import string
from datetime import datetime

import requests
import json
import tkinter as tk
from tkinter import messagebox, Scrollbar, Listbox, END
import sys
import hashlib

import urllib3

# Suppress only the InsecureRequestWarning from urllib3 used by requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Call the function to get the current date and time
def get_current_date_and_time():
    current_datetime = datetime.datetime.now()
    return current_datetime


def record(tag):
    print(tag)


def lls():
    args = sys.argv[1:]  # Exclude the script name itself
    tell = None
    if '-t' in args:
        tell = True
    return tell

if lls():
    print('''
    The authentication process involves sending user ID and password hashed using SHA-3-512 to a server 
    endpoint and receiving a response indicating successful or failed authentication. Upon successful authentication, 
    the user can access the chat window where they can send and receive encrypted messages. The encryption process 
    involves XORing the message characters with characters from a key file, ensuring secure communication. 

    The application also provides options for specifying encryption keys, always encrypting messages, and passing 
    encryption to the client. It continuously checks for new messages and updates the chat window accordingly. The GUI 
    elements are organized using frames, labels, entry fields, buttons, listboxes, and a scrollbar. Finally, the script 
    runs an instance of the MessageApp class as the main application loop.''')
    record("lls() displayed the message successfully")

def hash_string(input_string):
    # Encode the input string to bytes
    input_bytes = input_string.encode()

    # Create a new SHA-3-512 hash object
    sha3_512_hash = hashlib.sha3_512()

    # Update the hash object with the input bytes
    sha3_512_hash.update(input_bytes)

    # Get the hexadecimal representation of the hash
    hashed_string = sha3_512_hash.hexdigest()

    return hashed_string


BASE_URL = "https://sharepanel.host/dev/MS"
AUTH_URL = BASE_URL + "/authen.php"
MESSAGE_URL = BASE_URL + "/message.php"


def get_key_and_verbose_from_args():
    args = sys.argv[1:]  # Exclude the script name itself
    key = None
    verbose = False
    light = False

    if '-k' in args:
        index = args.index('-k')
        if index < len(args) - 1:
            key = args[index + 1]
        else:
            key = None

    if '-v' in args:
        verbose = True

    if '--light' in args:
        light = True

    return key, verbose, light

def upload_string(text, time, rec_id):
    url = 'https://sharepanel.host/dev/MS/transaction.php'
    params = {
        'action': 'write',
        'text': text,
        'time': time,
        'rec_id': rec_id  # Adding rec_id parameter
    }

    response = requests.get(url, params=params, verify=False)

    if response.status_code == 200:
        code = response.text
        return code
    else:
        return None


def read_string(code, rec_id, password):
    url = 'https://sharepanel.host/dev/MS/transaction.php'
    params = {
        'action': 'read',
        'code': code,
        'rec_id': rec_id,
        'password': password
    }

    response = requests.get(url, params=params, verify=False)

    if response.status_code == 200:
        return response.text
    elif response.status_code == 403:
        return 'Invalid rec_id or password.'
    elif response.status_code == 404:
        return 'Transaction not found or expired.'
    else:
        return 'Failed to fetch content.'

class MessageApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Message App")
        self.geometry("400x500")
        self.last_message_timestamp = "1900-01-01 00:00:00"
        self.create_auth_widgets()
        self.recipient_id = None
        self.AllwaysEncrypt_ = False
        self.apper = False
        self.key,self.verbose,self.light = get_key_and_verbose_from_args()


    def encrypt_with_file(self,file_path, string, key):
        if self.verbose:
            print("Starting encryption process...")

        if key is None:
            if self.verbose:
                print("No encryption key provided. Skipping encryption.")
            return string
        else:
            if self.verbose:
                print(f"Using key from file '{file_path}' for encryption.")

            with open(file_path, 'r') as file:
                key = file.read()

            encrypted = ''.join(chr(ord(char) ^ ord(key[i % len(key)])) for i, char in enumerate(string))

            if self.verbose:
                print("Encryption successful.")

            return encrypted


    def decrypt_with_file(self, file_path, encrypted_string, key):
        if self.verbose:
            print("Starting decryption process...")

        if key is None:
            if self.verbose:
                print("No decryption key provided. Skipping decryption.")
            return encrypted_string
        else:
            if self.verbose:
                print(f"Using key from file '{file_path}' for decryption.")

            with open(file_path, 'r') as file:
                key = file.read()

            # Ensure key is not empty to avoid ZeroDivisionError
            if len(key) == 0:
                if self.verbose:
                    print("Decryption key is empty. Skipping decryption.")
                return encrypted_string

            decrypted = ''.join(chr(ord(char) ^ ord(key[i % len(key)])) for i, char in enumerate(encrypted_string))

            if self.verbose:
                print("Decryption successful.")

            return decrypted



    def create_auth_widgets(self):
        self.auth_frame = tk.Frame(self)
        self.auth_frame.pack(fill=tk.BOTH, expand=True)

        self.user_id_label = tk.Label(self.auth_frame, text="User ID:")
        self.user_id_label.pack()
        self.user_id_entry = tk.Entry(self.auth_frame)
        self.user_id_entry.pack()

        self.password_label = tk.Label(self.auth_frame, text="Password:")
        self.password_label.pack()
        self.password_entry = tk.Entry(self.auth_frame, show="*")
        self.password_entry.pack()

        self.auth_button = tk.Button(self.auth_frame, text="Authenticate", command=self.authenticate_user)
        self.auth_button.pack()

        md = requests.get('https://sharepanel.host/dev/MS/Status.php', verify=False)
        if md.status_code == 200:
            md = md.text
        elif md.status_code != 200:
            md = "Connection Is Broken"


        self.aut = tk.Message(self.auth_frame, text=f'''{md}


{os.getcwdb()}
''')
        self.aut.pack()

        self.autrh_button = tk.Button(self.auth_frame, text="Help?", command=self.help)
        self.autrh_button.pack()

    def help(self):
        import webbrowser

        # Open a URL in the default web browser
        url = "https://sharepanel.host/dev/MS/help/?"
        webbrowser.open(url)


    def authenticate_user(self):
        user_id = self.user_id_entry.get()
        password = self.password_entry.get()

        data = {
            "id": user_id,
            "password": hash_string(password)
        }

        if self.verbose:
            print(f"Authenticating user with ID: {user_id}")

        response = requests.post(AUTH_URL, json=data, verify=False)

        if response.text == 'Authentication successful':
            if self.verbose:
                print("Authentication successful. Creating chat window.")
            messagebox.showinfo("Authentication Successful", "Authentication successful!")
            self.auth_frame.destroy()
            if self.light:
                self.create_chat_window_light(user_id, hash_string(password))
            else:
                self.create_chat_window_dark(user_id, hash_string(password))
        else:
            if self.verbose:
                print("Authentication failed. Please check your ID and password.")
            messagebox.showerror("Authentication Failed", "Authentication failed. Please check your ID and password.")


    def DefineNewKey(self, file_path):
        self.key = file_path  # Update the key attribute with the content of the file

    def create_chat_window_dark(self, user_id, password):
        self.chat_frame = tk.Frame(self)
        self.chat_frame.pack(fill=tk.BOTH, expand=True)

        self.message_label = tk.Label(self.chat_frame, text="Enter message:")
        self.message_label.pack()
        self.message_entry = tk.Entry(self.chat_frame)
        self.message_entry.pack()

        self.recipient_label = tk.Label(self.chat_frame, text="Recipient ID:")
        self.recipient_label.pack()
        self.recipient_entry = tk.Entry(self.chat_frame)
        self.recipient_entry.pack()

        self.send_button = tk.Button(self.chat_frame, text="Send Message",
                                     command=lambda: self.send_message(user_id, password, temp1=False))
        self.send_button.pack()

        self.enc = tk.Button(self.chat_frame, text="Allways Encrypt",
                             command=lambda: self.AllwaysEncrypt())
        self.enc.pack()

        self.reset_button = tk.Button(self.chat_frame, text="Reset Chat", command=self.clear_chat)
        self.reset_button.pack()

        self.er = tk.Button(self.chat_frame, text="Pass Encryption to Client", command=self.Apply)
        self.er.pack()

        self.file_path_label = tk.Label(self.chat_frame, text="KeyFilePath: ")
        self.file_path_label.pack()

        # Update the theme button text
        self.theme_button = tk.Button(self.chat_frame, text="Toggle Theme", command=self.toggle_theme)
        self.theme_button.pack()

        self.file_path_entry = tk.Entry(self.chat_frame)
        self.file_path_entry.pack()

        self.load_button = tk.Button(self.chat_frame, text="Load New Key",
                                     command=lambda: self.DefineNewKey(self.file_path_entry.get()))
        self.load_button.pack()

        self.message_display = Listbox(self.chat_frame, width=80, height=15)
        self.message_display.pack()

        self.scrollbar = Scrollbar(self.chat_frame, orient="vertical", command=self.message_display.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.message_display.config(yscrollcommand=self.scrollbar.set)



        # Set the initial theme
        self.set_light_theme()

        self.after(1000, lambda: self.check_messages(user_id, password))

    def set_dark_theme(self):
        self.chat_frame.configure(bg="#333333")
        self.message_label.configure(bg="#333333", fg="#f4f4f4")
        self.message_entry.configure(bg="#f4f4f4", fg="#333333")
        self.recipient_label.configure(bg="#333333", fg="#f4f4f4")
        self.recipient_entry.configure(bg="#f4f4f4", fg="#333333")
        self.send_button.configure(bg="#007aff", fg="white")
        self.enc.configure(bg="#007aff", fg="white")
        self.reset_button.configure(bg="#007aff", fg="white")
        self.er.configure(bg="#007aff", fg="white")
        self.file_path_label.configure(bg="#333333", fg="#f4f4f4")
        self.file_path_entry.configure(bg="#f4f4f4", fg="#333333")
        self.load_button.configure(bg="#007aff", fg="white")
        self.message_display.configure(bg="white", fg="#333333")
        self.scrollbar.configure(bg="#333333")

    def set_light_theme(self):
        self.chat_frame.configure(bg="#f4f4f4")
        self.message_label.configure(bg="#f4f4f4", fg="#333333")
        self.message_entry.configure(bg="white", fg="#333333")
        self.recipient_label.configure(bg="#f4f4f4", fg="#333333")
        self.recipient_entry.configure(bg="white", fg="#333333")
        self.send_button.configure(bg="#007aff", fg="white")
        self.enc.configure(bg="#007aff", fg="white")
        self.reset_button.configure(bg="#007aff", fg="white")
        self.er.configure(bg="#007aff", fg="white")
        self.file_path_label.configure(bg="#f4f4f4", fg="#333333")
        self.file_path_entry.configure(bg="white", fg="#333333")
        self.load_button.configure(bg="#007aff", fg="white")
        self.message_display.configure(bg="white", fg="#333333")
        self.scrollbar.configure(bg="#f4f4f4")

    def set_ocean_blue_theme(self):
        self.chat_frame.configure(bg="#0077be")
        self.message_label.configure(bg="#0077be", fg="#ffffff")
        self.message_entry.configure(bg="#ffffff", fg="#333333")
        self.recipient_label.configure(bg="#0077be", fg="#ffffff")
        self.recipient_entry.configure(bg="#ffffff", fg="#333333")
        self.send_button.configure(bg="#ffffff", fg="#0077be")
        self.enc.configure(bg="#ffffff", fg="#0077be")
        self.reset_button.configure(bg="#ffffff", fg="#0077be")
        self.er.configure(bg="#ffffff", fg="#0077be")
        self.file_path_label.configure(bg="#0077be", fg="#ffffff")
        self.file_path_entry.configure(bg="#ffffff", fg="#333333")
        self.load_button.configure(bg="#ffffff", fg="#0077be")
        self.message_display.configure(bg="#ffffff", fg="#333333")
        self.scrollbar.configure(bg="#0077be")

    def toggle_theme(self):
        current_bg = self.chat_frame.cget('bg')
        if current_bg == "#f4f4f4":
            self.set_dark_theme()
        elif current_bg == "#333333":
            self.set_ocean_blue_theme()
        else:
            self.set_light_theme()


    def genkey(self, rules):
        key = ''
        characters = ''
        length = 512
        for rule in rules:
            if rule == 1:
                characters += string.ascii_letters
            elif rule == 2:
                characters += string.ascii_letters + string.digits
            elif rule == 3:
                characters += string.ascii_letters + string.digits + string.punctuation
            elif rule == 4:
                characters += string.digits
            elif rule == 5:
                characters += ''.join([chr(i) for i in range(128, 256)])  # Non-English characters

        # Combine rules 2 and 4
        if 2 in rules and 4 in rules:
            characters += string.ascii_letters + string.digits

        for _ in range(length):
            key += random.choice(characters)

        return key


    def ide(self,User_id):
        with open(f'key', 'w') as r:
            self.key = 'key'
            key34 = self.genkey(rules=[2])
            r.write(key34)
            keyl = upload_string(key34, (60 * 60),User_id)
            if self.verbose:
                print(f"Key has been uploaded to server with id {keyl}")
            r.close()
        return(keyl)


    def Apply(self):
        self.apper = True


    def AllwaysEncrypt(self):
        self.AllwaysEncrypt_ = True


    def split_string(self,input_str):
        if '[:]' in input_str:
            return input_str.split('[:]')[0], input_str.split('[:]')[1]
        else:
            return None,input_str


    def send_message(self, user_id, password,temp1):
        message = self.message_entry.get()
        recipient_id = self.recipient_entry.get()

        if recipient_id is None:
            recipient_id = self.recipient_id_m
        elif recipient_id == '':
            recipient_id = self.recipient_id_m
        else:
            self.recipient_id_m = recipient_id

        if self.apper:
            self.apper = False
            id_ = self.ide(recipient_id)
            message = f'{id_}[:]{self.encrypt_with_file(self.key, message, self.key)}'
        elif self.AllwaysEncrypt_:
            self.apper = False
            id_ = self.ide(recipient_id)
            message = f'{id_}[:]{self.encrypt_with_file(self.key, message, self.key)}'
        else:
            message = self.encrypt_with_file(self.key, message, self.key)


        if temp1:
            data = {
                "send_id": user_id,
                "rec_id": recipient_id,
                "message": message,
                "password": password,
                "temp": "true"
            }
        else:
            data = {
                "send_id": user_id,
                "rec_id": recipient_id,
                "message": message,
                "password": password
            }

        if self.verbose:
            print(f"Sending message from {user_id} to {recipient_id}")
            print(f"Message content: {message}")

        response = requests.post(MESSAGE_URL, json=data, verify=False)

        if response.status_code == 200:
            if self.verbose:
                print("Message sent successfully.")
            messagebox.showinfo("Message Sent", "Message sent successfully!")
            self.message_entry.delete(0, END)
            self.recipient_entry.delete(0, END)
        else:
            if self.verbose:
                print("Failed to send message.")
            messagebox.showerror("Failed to Send Message", "Failed to send message.")


    def check_messages(self, user_id, password):
        response = requests.get(f"{MESSAGE_URL}?id={user_id}&password={password}", verify=False)

        if self.verbose:
            print(f"Checking messages for user {user_id}")

        if response.status_code == 200:
            try:
                data = response.json()
                if isinstance(data, list):
                    for message in data:
                        key,message2 = self.split_string(message['message'])
                        sender = "You" if message["send_id"] == user_id else message["send_id"]
                        rec = "You" if message["rec_id"] == user_id else message["rec_id"]

                        if key is not None:
                            if message['timestamp'] > self.last_message_timestamp:
                                if sender != 'You':
                                    with open(f'key', 'w') as r:
                                        key = read_string(key,user_id,password)

                                        if key != 'Transaction not found or expired.':
                                            if key != 'Invalid rec_id or password.':
                                                self.key = 'key'
                                                r.write(key)
                                                if self.verbose:
                                                    print(f'written {key}')
                                                r.close()
                                            else:
                                                print(user_id, password)
                                                if self.verbose:
                                                    print(f'Invalid rec_id or password.')
                                        else:
                                            if self.verbose:
                                                print(f'Transaction not found or expired.')

                        if message['timestamp'] > self.last_message_timestamp:
                            decrypted_message = self.decrypt_with_file(self.key, message2, self.key)
                            if self.verbose:
                                print(f"New message received: [{message['timestamp']}] {sender} to {rec}")
                                print(f"Decrypted message content: {decrypted_message}")
                                print(f"Non-Decrypted message content: {message2}")
                            self.message_display.insert(END,
                                                        f"[{message['timestamp']}] {sender} to {rec} -> {decrypted_message}")
                            self.last_message_timestamp = message['timestamp']
                elif isinstance(data, dict) and "messages" in data:
                    messages = data["messages"]
                    for message in messages:
                        key, message = self.split_string(message)
                        if key is not None:
                            with open(f'key', 'w') as r:
                                self.key = key
                                r.write(key)
                                r.close()
                            self.key = 'key'
                        sender = "You" if message["send_id"] == user_id else message["send_id"]
                        rec = "You" if message["rec_id"] == user_id else message["rec_id"]
                        if message['timestamp'] > self.last_message_timestamp:
                            decrypted_message = self.decrypt_with_file(self.key, message['message'], self.key)
                            if self.verbose:
                                print(f"New message received: [{message['timestamp']}] {sender} to {rec}")
                                print(f"Decrypted message content: {decrypted_message}1")
                            self.message_display.insert(END,
                                                        f"[{message['timestamp']}] {sender} to {rec} -> {decrypted_message}")
                            self.last_message_timestamp = message['timestamp']
            except json.decoder.JSONDecodeError:
                pass  # No new messages
        self.after(1000, lambda: self.check_messages(user_id, password))


    def clear_chat(self):
        # Clear all items from the Listbox
        self.last_message_timestamp = "1900-01-01 00:00:00"
        self.message_display.delete(0, 'end')


if __name__ == "__main__":
    app = MessageApp()
    app.mainloop()
