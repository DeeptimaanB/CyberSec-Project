from scapy.all import *
import secrets
import string
import mysql.connector
import time
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from Protocol import DEKX

server = "10.0.0.166"

# Establish connection to the MySQL database
connection = mysql.connector.connect(
    host=server,
    user="php_docker",
    password="php_docker",
    database="php_docker"
)

# Create a cursor object to execute SQL queries
cursor = connection.cursor()

def search_user(username):
    try:
        # Define the SQL query to retrieve id and name
        sql_query = "SELECT id, password, salt, offset FROM user_keys WHERE id = %s"
        cursor.execute(sql_query, (username,))

        # Fetch the result (assuming only one row is returned)
        result = cursor.fetchone()

        # Return id and name as a tuple
        if result:
            return result
        else:
            return None  # No data found

    except mysql.connector.Error as error:
        print("Error while connecting to MySQL:", error)
        return None

    finally:
        # Close the cursor and connection
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

def update_salt_sql(user_id, salt):
    try:
        # Define the SQL query to update the name based on user ID
        sql_query = "UPDATE user_keys SET salt = %s WHERE id = %s"
        cursor.execute(sql_query, (salt, user_id))

        # Commit the transaction
        connection.commit()

        print("Salt updated successfully.")

    except mysql.connector.Error as error:
        # Rollback the transaction in case of error
        print("Error while connecting to MySQL:", error)

    finally:
        # Close the cursor and connection
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()     

def update_salt_offset_sql(user_id, salt, offset_temp):
    try:
        # Define the SQL query to update the name based on user ID
        sql_query = "UPDATE user_keys SET salt = %s, offset = %s WHERE id = %s"
        cursor.execute(sql_query, (salt, offset_temp, user_id))

        # Commit the transaction
        connection.commit()

        print("Salt updated successfully.")

    except mysql.connector.Error as error:
        # Rollback the transaction in case of error
        print("Error while connecting to MySQL:", error)

    finally:
        # Close the cursor and connection
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()     

# Function to update salt.
def update_salt(id):
    salt_text = generate_salt()
    update_salt_sql(id, salt_text)
    return salt_text

# Updating the salt and the offset by generating temperory offset.
def update_salt_offset(id):
    salt_text = generate_salt()
    offset_temp = str(random.randint(0, 63))
    update_salt_offset_sql(id, salt_text, offset_temp)
    return salt_text, int(offset_temp)

# Function to generate an md5 hash for the text password along with the salt.
def generate_md5(text,salt):
    text = text+salt
    md5_hash = hashlib.md5()
    md5_hash.update(text.encode())
    md5_hex = md5_hash.hexdigest()
    return md5_hex

# Function to extract the password from t e hash.
def extract_password(input_string, start_point):
    extracted_password = input_string[start_point:start_point+32]
    return extracted_password

# Function to generate salt using length 5.
def generate_salt(length=5):
    valid_characters = string.ascii_letters + string.digits
    salt = ''.join(secrets.choice(valid_characters) for _ in range(length))
    return str(salt)

# Define a function to handle received packets
def packet_handler(pkt):
    if pkt.haslayer(DEKX):
        print("DEKX Packet")
        user_id = pkt[DEKX].user_id # User id of the user.
        password = pkt[DEKX].password # Password of the user.
        password = password.decode('utf-8') # Convert the password to utf-8 for string.
        offset = pkt[DEKX].offset # Extract the offset from the packet.
        if(offset == 97): # The offset is 97 in the initial state, this is done so that we can send a random offset.
            password = extract_password(str(password), 0)
        
        # Extract the result using the search_function.
        result = search_user(int(user_id))
        if result:
            user_id_text, password_md5, salt_text, offset_text = result
            if(salt_text == None):
                salt_text=""
            if(offset_text == None):
                offset_text=97
            password = extract_password(str(password), offset_text)

            # We will check two cases when the salt is empty and if the salt is not empty.
            if(salt_text!=""):
                temp_password = generate_md5(password_md5, salt_text)
                if (int(user_id) == user_id_text and password == temp_password):
                    temp_salt = update_salt(str(user_id))
                    time.sleep(2)
                    custom_pkt = Ether(dst = "ff:ff:ff:ff:ff:ff", type=0xDE77)/DEKX(user_id=int(user_id), salt = temp_salt, offset = 98)
                    sendp(custom_pkt, iface="eth0")
                    time.sleep(0.5)  # Simulate some work being done
                    print("New Salt Sent " + temp_salt)
            elif(salt_text==""):
                if (int(user_id) == user_id_text and password == password):
                    temp_salt, temp_offset = update_salt_offset(str(user_id))
                    time.sleep(2)
                    custom_pkt = Ether(dst = "ff:ff:ff:ff:ff:ff", type=0xDE77)/DEKX(user_id=int(user_id), salt = temp_salt, offset = temp_offset)
                    sendp(custom_pkt, iface="eth0")
                    time.sleep(0.5)  # Simulate some work being done
                    print("New Salt Sent " + temp_salt)
                
        else:
            print("No Data Found for userid : " + str(user_id))

# Bind a filter to DEKX layer
bind_layers(Ether, DEKX, type=0xDE77)

# Sniff packets on the network
sniff(prn=packet_handler, store=0)