import os
import string
import time
from datetime import datetime
import hashlib
import secrets
import random

import requests
import json
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)


BASE_URL = "https://doesnte235246.000webhostapp.com"
AUTH_URL = BASE_URL + "/authen.php"
MESSAGE_URL = BASE_URL + "/message.php"
token = secrets.token_hex(128)
time_stamp_token = secrets.token_hex(128)
time_stamp_last = None

def write_data(token1, username1, data1):
    url = 'https://doesnte235246.000webhostapp.com/lock.php'
    payload = {
        'mode': 'write',
        'token': token1,
        'user': username1,
        'data': data1
    }
    headers = {'Content-Type': 'application/json'}
    response = requests.post(url, data=json.dumps(payload), headers=headers)
    print(response.json())


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


def upload_string(text, time, rec_id):
    url = 'https://doesnte235246.000webhostapp.com/transaction.php'
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
    url = 'https://doesnte235246.000webhostapp.com/transaction.php'
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


def ide(User_id):
        with open(f'key', 'w') as r:
            key = 'key'
            key34 = genkey(rules=[2])
            r.write(key34)
            keyl = upload_string(key34, (60 * 60),User_id)
            print(f"Key has been uploaded to server with id {keyl}")
            r.close()
        return (keyl)

def encrypt_with_file(file_path, string, key):


    if key is None:

        return string
    else:

        with open(file_path, 'r') as file:
            key = file.read()

        encrypted = ''.join(chr(ord(char) ^ ord(key[i % len(key)])) for i, char in enumerate(string))


        return encrypted

def decrypt_with_file(file_path, encrypted_string, key):
    if key is None:
        return encrypted_string
    else:
        with open(file_path, 'r') as file:
            key = file.read()

        decrypted = ''.join(chr(ord(char) ^ ord(key[i % len(key)])) for i, char in enumerate(encrypted_string))

        return decrypted


def enc(rec,key,message):
    id_ = ide(rec)
    message = f'{id_}[:]{encrypt_with_file(key, message, key)}'
    return message

def split_string(input_str):
    if '[:]' in input_str:
        return input_str.split('[:]')[0], input_str.split('[:]')[1]
    else:
        return None,input_str


def is_second_time_after_first(first_time, second_time):
    global time_stamp_last
    if first_time is None:
        return True
    else:
        first_time_obj = datetime.strptime(first_time, "%Y-%m-%d %H:%M:%S")
        second_time_obj = datetime.strptime(second_time, "%Y-%m-%d %H:%M:%S")
        if (second_time_obj > first_time_obj):
            time_stamp_last = second_time
        return second_time_obj > first_time_obj


def check_messages(user_id, password):
    global time_stamp_token,time_stamp_last
    response = requests.get(f"{MESSAGE_URL}?id={user_id}&password={hash_string(password)}", verify=False)
    data = json.loads(response.text)
    lines = ''
    mx = len(data)
    for entry in data:
        if time_stamp_last is None:
            if (mx-data.index(entry)) == 1:
                time_stamp_last = entry["timestamp"]
                print("timestamp set to {}".format(time_stamp_last))
            if user_id == entry["send_id"]:
                line = (f'{entry["timestamp"]}| You -> {entry["message"]}')
            else:
                line = (f'{entry["timestamp"]}| {entry["send_id"]} -> {entry["message"]}')
            lines += f'\n{line}'
        else:
            if is_second_time_after_first(time_stamp_last,entry["timestamp"]):
                if mx == data.index(entry):
                    time_stamp_last = entry["timestamp"]
                    print("timestamp set to {}".format(time_stamp_last))
                if user_id == entry["send_id"]:
                    line = (f'{entry["timestamp"]}| You -> {entry["message"]}')
                else:
                    line = (f'{entry["timestamp"]}| {entry["send_id"]} -> {entry["message"]}')
                lines += f'\n{line}'
            else:
                pass
    return lines


def read_data():
    global token
    url = 'https://doesnte235246.000webhostapp.com/re.php'
    payload = {
        'mode': 'read',
        'token': token
    }
    headers = {'Content-Type': 'application/json'}
    response = requests.post(url, data=json.dumps(payload), headers=headers)
    data = response.json()


    user = data.get('user', None)
    data_value = data.get('data', None)
    new_token = data.get('token', None)

    token = new_token
    return user, data_value, new_token


def hash_string(input_string):
    if input_string is not None:
        # Encode the input string to bytes
        input_bytes = input_string.encode()

        # Create a new SHA-3-512 hash object
        sha3_512_hash = hashlib.sha3_512()

        # Update the hash object with the input bytes
        sha3_512_hash.update(input_bytes)

        # Get the hexadecimal representation of the hash
        hashed_string = sha3_512_hash.hexdigest()

        return hashed_string
    return None


def authenticate_user(user_id, password):
    data = {
        "id": user_id,
        "password": hash_string(password)
    }

    response = requests.post(AUTH_URL, json=data, verify=False)

    if response.text == 'Authentication successful':
        return True
    else:
        return False


def send_message(message,recipient_id,user,passw):
    time.sleep(1.5)

    data = {
        "send_id": user,
        "rec_id": recipient_id,
        "message": message,
        "password": hash_string(passw)
    }

    response = requests.post(MESSAGE_URL, json=data, verify=False)
    print('================================================')
    print(response.text)
    print('================================================')
    print(data)
    print('================================================')
    if response.status_code == 200:
        return True
    else:
        return False


# Endpoint to require username and password
@app.route('/secure', methods=['GET', 'POST'])
def secure():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username is None:
            pass
        else:
            auth = authenticate_user(username, password)
            if auth:
                write_data(token, username, password)
                return render_template('display_data.html', key=token)

    return render_template('secure.html')


# Endpoint to return random data
@app.route('/random-data')
def random_data():
    global token  # Making token accessible within the function
    user, data_value, new_token = read_data()

    token = new_token
    message = check_messages(user, data_value)
    if message == '' or None:
        return '[!]'
    else:
        return message


# Endpoint to receive data from the form
@app.route('/send-data', methods=['POST'])
def send_data():
    global token

    recipient = request.form['recipient']
    message = request.form['message']
    user, passw, new_token = read_data()
    send_message(message,recipient,user,passw)
    return "Data sent successfully!"


@app.route('/')
def index():
    return render_template('index.html')




if __name__ == "__main__":
    url = 'http://127.0.0.1:5000'
    app_path = 'open -a Safari %s'

    os.system(app_path % url)
    app.run(debug=True)
