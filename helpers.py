import datetime
import hashlib

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
