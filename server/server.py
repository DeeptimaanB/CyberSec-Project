from scapy.all import *
import secrets
import string
import mysql.connector
import threading

# Add the root folder to sys.path to be able to import Protocol
# Get the directory of the current file (__file__) and add the parent directory to sys.path
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from Protocol import DEKX
from helpers import *


# Create the connection to the MySQL DB
connection = mysql.connector.connect(
    host="110.0.0.72",
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

def update_salt(id):
    salt_text = generate_salt()
    # update_salt_sql(id, salt_text)
    return salt_text

def extract_password(input_string, start_point):
    extracted_password = input_string[start_point:start_point+32]
    return extracted_password

    def mysummary(self):
        return self.sprintf("user_id=%user_id% password=%password%")

def generate_salt(length=5):
    valid_characters = string.ascii_letters + string.digits
    salt = ''.join(secrets.choice(valid_characters) for _ in range(length))
    return str(salt)

def send_packet():
    sendp(custom_pkt, iface="eth0")
    time.sleep(2)  # Simulate some work being done

custom_pkt = Ether(dst = "ff:ff:ff:ff:ff:ff", type=0xDE77)/DEKX()
# Bind a filter to DEKX layer
bind_layers(Ether, DEKX, type=0xDE77)

# Sniff packets on the network
sniff(prn=packet_handler_server, store=0)