# Add the root folder to sys.path to be able to import Protocol
# Get the directory of the current file (__file__) and add the parent directory to sys.path
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from Protocol import DEKX
import hashlib

# This will generate an md5 password
def generate_md5(text):
    md5_hash = hashlib.md5()
    md5_hash.update(text.encode())
    md5_hex = md5_hash.hexdigest()
    return md5_hex

# Define a function to handle received packets (SEND)
def packet_handler_send(pkt, current_salt):
    print("Inside send packet_handler")
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
            sniff_process.stop()

# Define a function to handle received packets
def packet_handler_server(pkt):
    if pkt.haslayer(DEKX):
        user_id = pkt[DEKX].user_id
        password = pkt[DEKX].password
        password = password.decode('utf-8')
        password = extract_password(str(password), 3)
        result = search_user(int(user_id))
        if result:
            user_id_text, password_md5, salt_text, offset_text = result 
            temp_password = generate_md5(password_md5, salt_text)
            if (int(user_id) == user_id_text and password == temp_password):
                temp_salt = update_salt(str(user_id))
                custom_pkt = Ether(dst = "ff:ff:ff:ff:ff:ff", type=0xDE77)/DEKX(user_id=int(user_id), salt = temp_salt, offset = 98)
                thread = threading.Thread(target=send_packet)
                thread.start()
                thread.join()
                print("New Salt Sent " + temp_salt)
        else:
            print("No Data Found for userid : " + str(user_id))
