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
from helpers import *
import datetime

server = "0.0.0.0"
interface = "wlan1"


# Establish connection to the MySQL database
connection = mysql.connector.connect(
    host=server,
    user="php_docker",
    password="php_docker",
    database="php_docker"
)

def configure_access_point():
    import os
    os.system("nmcli device wifi hotspot ifname "+interface+" ssid MyServerAP password APpassword123")
    print("Access Point configured. Clients can connect to SSID 'MyServerAP'.")

configure_access_point()

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
    offset_temp = str(random.randint(0, 127))
    update_salt_offset_sql(id, salt_text, offset_temp)
    return salt_text, int(offset_temp)


# Function to generate an sha256 hash for the text password along with the salt.
def generate_sha256(text,salt):
    text = text+salt
    sha256_hash = hashlib.sha256()
    sha256_hash.update(text.encode())
    sha256_hex = sha256_hash.hexdigest()
    return sha256_hex

# Function to extract the password from t e hash.
def extract_password(input_string, start_point):
    extracted_password = input_string[start_point:start_point+64]
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
        p_time = pkt[DEKX].datetime # Time of the packet.
        offset = pkt[DEKX].offset # Extract the offset from the packet.

        if (offset == 260):
            p_time = decrypt_data("server_private_key.pem", p_time)
            p_time = p_time.decode('utf=8')
            print("Date-Time : "+p_time)
            print("User Connecting : "+str(user_id))
            print("Offset : "+str(offset))
            s_time = float(datetime.datetime.now().timestamp())
            p_time = float(p_time)

            if (s_time - p_time > 5):
                print("Packet Expired.")
                return

            print("Acknowledgement Received.")

        if (offset == 259 or offset == 257):
            print(hexlify(password).decode())
            password = decrypt_data("server_private_key.pem", password)
            # Convert the password to utf-8 for string.
            password = password.decode("utf-8")
            p_time = decrypt_data("server_private_key.pem", p_time)
            p_time = p_time.decode('utf=8')
            print("Date-Time : "+p_time)
            print("User Connecting : "+str(user_id))
            print("Password Received : "+password)
            print("Offset : "+str(offset))
            s_time = float(datetime.datetime.now().timestamp())
            p_time = float(p_time)

            if (s_time - p_time > 20):
                print("Packet Expired.")
                return
                

        if(offset == 257): # The offset is 257 in the initial state, this is done so that we can send a random offset.
            password = extract_password(str(password), 0)


        # Extract the result using the search_function.
        result = search_user(int(user_id))
        if result:
            user_id_text, password_sha256, salt_text, offset_text = result
            if(salt_text == None):
                salt_text=""
            if(offset_text == None):
                offset_text=0
            password = extract_password(str(password), offset_text)

            temp_password = generate_sha256(password_sha256,salt_text)
            
            # We will check two cases when the salt is empty and if the salt is not empty.
            if(salt_text!=""):
                if (int(user_id) == int(user_id_text) and password == temp_password):
                    temp_salt = update_salt(str(user_id))
                    print("New Salt: " + temp_salt)
                    temp_salt = temp_salt.encode()
                    temp_salt = encrypt_data("key_public_key.pem", temp_salt)
                    time.sleep(2)
                    custom_pkt = Ether(dst = "ff:ff:ff:ff:ff:ff", type=0xDE77)/DEKX(user_id=int(user_id), salt = temp_salt, offset = 258)
                    sendp(custom_pkt, iface=interface)
                    time.sleep(0.5)  # Simulate some work being done
                    print("New Salt Sent: " + hexlify(temp_salt).decode())

            elif(salt_text==""):
                if (int(user_id) == int(user_id_text) and password == password_sha256):
                    temp_salt, temp_offset = update_salt_offset(str(user_id))
                    print("New Salt: " + temp_salt)
                    temp_salt = temp_salt.encode()
                    temp_salt = encrypt_data("key_public_key.pem", temp_salt)
                    time.sleep(2)
                    custom_pkt = Ether(dst = "ff:ff:ff:ff:ff:ff", type=0xDE77)/DEKX(user_id=int(user_id), salt = temp_salt, offset = temp_offset)
                    sendp(custom_pkt, iface=interface)
                    time.sleep(0.5)  # Simulate some work being done
                    print("New Salt Sent: " + hexlify(temp_salt).decode())
                    print("New Offset Sent: " + str(temp_offset))
                
        else:
            print("No Data Found for userid : " + str(user_id))

# Bind a filter to DEKX layer
bind_layers(Ether, DEKX, type=0xDE77)

# Sniff packets on the network
sniff(iface=interface, prn=packet_handler, store=0)