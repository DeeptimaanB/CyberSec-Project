import datetime
import hashlib
# Import necessary modules from pycryptodome
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from binascii import hexlify

def gen_keys(private_key, public_key):
    key = RSA.generate(2048)
    with open(private_key+".pem" ,"wb") as f:
        f.write(key.export_key(format="PEM"))

    with open(public_key+".pem" ,"wb") as f:
        f.write(key.public_key().export_key(format="PEM"))


def load_private_key(filename):
    with open(filename, "rb") as f:
        return RSA.import_key(f.read())

# Load the public key
def load_public_key(filename):
    with open(filename, "rb") as f:
        return RSA.import_key(f.read())

def encrypt_data(public_key_file, data):
    public_key = load_public_key(public_key_file)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted = cipher_rsa.encrypt(data)
    return encrypted

# Function to decrypt data
def decrypt_data(private_key_file, encrypted_data):
    private_key = load_private_key(private_key_file)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted = cipher_rsa.decrypt(encrypted_data)
    return decrypted


# Function used to replace characters with random characters in the hashed password.
def replace_characters(original_string, replacement_string, start_point):
    end_point = start_point + len(replacement_string)
    modified_string = original_string[:start_point] + replacement_string + original_string[end_point:]
    return modified_string

# Function to create the md5 hash of the password.
def generate_md5(text):
    md5_hash = hashlib.md5()
    md5_hash.update(text.encode())
    md5_hex = md5_hash.hexdigest()
    return md5_hex

# Function to generate a random md5 to add to the password in order to generate and use he salt.
def generate_random_md5():
    current_time = datetime.datetime.now()
    time_string = str(current_time)
    md5_hash = hashlib.md5()
    md5_hash.update(time_string.encode())
    md5_hex = md5_hash.hexdigest()
    return md5_hex

# Function to generate the password based on the salt.
def generate_password(new_string, salt, offset):
    superstring = generate_random_md5() + generate_random_md5() + generate_random_md5()
    new_string = new_string + salt
    if(salt!=""):
        new_string = generate_md5(new_string)
    superstring = replace_characters(superstring, new_string, offset)
    return superstring
