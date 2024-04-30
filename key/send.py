from scapy.all import *
import threading
import datetime

# Add the root folder to sys.path to be able to import Protocol
# Get the directory of the current file (__file__) and add the parent directory to sys.path
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from Protocol import DEKX
from helpers import *

def replace_characters(original_string, replacement_string, start_point):
    end_point = start_point + len(replacement_string)
    modified_string = original_string[:start_point] + replacement_string + original_string[end_point:]
    return modified_string

def generate_random_md5():
    current_time = datetime.datetime.now()
    time_string = str(current_time)
    md5_hash = hashlib.md5()
    md5_hash.update(time_string.encode())
    md5_hex = md5_hash.hexdigest()
    return md5_hex

def generate_password(new_string, salt, offset):
    superstring = generate_random_md5() + generate_random_md5() + generate_random_md5()
    new_string = new_string + salt
    new_string = generate_md5(new_string)
    superstring = replace_characters(superstring, new_string, offset)
    return superstring

def send_packet():
    for i in range(5):
        if sniffing_active:
            sendp(custom_pkt, iface="eth0")
            time.sleep(3)  # Simulate some work being done
        else:
            break

# Define a function to handle received packets
def packet_handler(pkt, current_salt):
    global sniffing_active
    global sniff_process
    if pkt.haslayer(DEKX):
        print("Received DEKX packet:")
        user_id = pkt[DEKX].user_id
        password = pkt[DEKX].password
        offset = pkt[DEKX].offset
        salt = pkt[DEKX].salt
        salt = salt.decode('utf-8')
        print(salt)
        if (str(current_salt) != salt and int(offset) == 98):
            current_salt = salt
            save_salt(str(current_salt))
            print("Salt Received")
            sniffing_active = False
            return True
    return False

def save_salt(salt):
    with open("salt.txt", "w") as file:
        file.write(salt)

def get_credentials():
    with open("credentials.txt", "r") as file:
        line1 = file.readline().rstrip("\n")
        line2 = file.readline().rstrip("\n")
    return line1, line2

def get_salt_offset(file_name):
    with open(file_name, "r") as file:
        line1 = file.readline().rstrip("\n")
    return line1

def extract_password(input_string, start_point):
    extracted_password = input_string[start_point:start_point+32]
    return extracted_password

# Create a custom packet specifying the EtherType
current_salt = get_salt_offset("salt.txt")
current_offset = int(get_salt_offset("offset.txt"))
user_id_text, password_md5 = get_credentials()
password_md5 = generate_password(password_md5, current_salt, 3)
print(password_md5)
custom_pkt = Ether(dst = "ff:ff:ff:ff:ff:ff", type=0xDE77)/DEKX(user_id=int(user_id_text), password=password_md5)
print(extract_password(password_md5, current_offset))
# Send the custom packet
bind_layers(Ether, DEKX, type=0xDE77)
stop = 1

while(stop!=0):
    # Sniff packets on the network
    thread = threading.Thread(target=send_packet)
    # Start the thread
    thread.start()
    time.sleep(2)
    sniff_process = sniff(prn=lambda packet: packet_handler_send(packet, current_salt), store=0, timeout = 10)
    print("Timeout Reached")
    stop = 0
    thread.join()
=======
sniffing_active = True

# Sniff packets on the network
thread = threading.Thread(target=send_packet)
# Start the thread
thread.start()
time.sleep(2)
sniff_process = sniff(stop_filter=lambda packet: packet_handler(packet, current_salt), store=0, timeout = 10)
thread.join()