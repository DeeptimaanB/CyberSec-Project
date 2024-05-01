# Importing all the required library and packages for the execution of the code.
from scapy.all import *
import threading
import datetime
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from Protocol import DEKX
from helpers import *


# Function to send the packet to the server
# This function is used to send a packet to the server, it sends a custom packet which we have created using the developed protocol.
def send_packet():
    for i in range(5):
        if sniffing_active:
            sendp(custom_pkt, iface="eth0")
            time.sleep(3)  # Simulate some work being done
        else:
            break

# Define a function to handle received packets
def packet_handler(pkt, current_salt):
    
    # Define a couple of global variables to determine if the sniffing is active and to stop and start the sniff process.
    global sniffing_active
    global sniff_process

    # Check it against the DEKX protocol and extract all the information required from the packet.
    if pkt.haslayer(DEKX):
        print("Received DEKX packet:")
        user_id = pkt[DEKX].user_id # User Id of the user.
        password = pkt[DEKX].password # Password of the user.
        offset = pkt[DEKX].offset # This is the offset that is used to place the salt and hash it.
        salt = pkt[DEKX].salt # This is the actual value of the salt, which is used for hashing.
        salt = salt.decode('utf-8')
        print(salt)

        # Check if the current salt is not equal to the salt in the protocol and check if offset ==98, assign the current salt to the one in the protocol.
        if (str(current_salt) != salt and int(offset) == 98):
            current_salt = salt
            save_salt(str(current_salt))
            print("Salt Received")
            sniffing_active = False
            return True
        # Check if the salt and current salt are equal and if the current salt is empty, assign it to the salt retrieved from the protocol.
        if (str(current_salt) != salt and current_salt==""):
            current_salt = salt
            save_salt(str(current_salt))
            save_offset(offset)
            print("Salt and Offset Received")
            sniffing_active = False
            return True
    return False

# Function to save the recieved salt into a text file for use.
def save_salt(salt):
    with open("salt.txt", "w") as file:
        file.write(salt)

# Function to save the retrieved offset into a file.
def save_offset(offset_val):
    with open("offset.txt", "w") as file:
        file.write(str(offset_val))

# Function to get the credentials from the text file.
def get_credentials():
    with open("credentials.txt", "r") as file:
        line1 = file.readline().rstrip("\n")
        line2 = file.readline().rstrip("\n")
    return line1, line2

# Function to read the salt and offset from the text file.
def get_salt_offset(file_name):
    with open(file_name, "r") as file:
        line1 = file.readline().rstrip("\n")
    return line1

# Function to extract the password from the hashed password.
def extract_password(input_string, start_point):
    extracted_password = input_string[start_point:start_point+32]
    return extracted_password

# Create a custom packet specifying the EtherType
current_salt = get_salt_offset("salt.txt")
current_offset = int(get_salt_offset("offset.txt"))

# Retrieve the user_id and password from the credentials file.
user_id_text, password_md5 = get_credentials()
custom_pkt = Ether()/DEKX()
if(current_salt!=""):
    password_md5 = generate_password(password_md5, current_salt, current_offset)
    custom_pkt = Ether(dst = "ff:ff:ff:ff:ff:ff", type=0xDE77)/DEKX(user_id=int(user_id_text), password=password_md5)
elif(current_salt==""):
    password_md5 = generate_password(password_md5, current_salt, 0)
    custom_pkt = Ether(dst = "ff:ff:ff:ff:ff:ff", type=0xDE77)/DEKX(user_id=int(user_id_text), password=password_md5, offset=97)

# Send the custom packet
bind_layers(Ether, DEKX, type=0xDE77)
stop = 1
sniffing_active = True

# Sniff packets on the network
thread = threading.Thread(target=send_packet)
# Start the thread
thread.start()
time.sleep(2)
sniff_process = sniff(stop_filter=lambda packet: packet_handler(packet, current_salt), store=0, timeout = 10)
thread.join()
