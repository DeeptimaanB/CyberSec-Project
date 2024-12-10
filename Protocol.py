from scapy.all import *

zeroes = "0" * 256
salt_zeroes = "0" * 512
# Define your custom protocol class
class DEKX(Packet):
    name = "DEKX"
    fields_desc = [
        IntField("user_id", 0),
        IntField("offset", 259),
        StrFixedLenField("password", zeroes, length=256),
        StrFixedLenField("salt", salt_zeroes, length=512)
    ]