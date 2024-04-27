from scapy.all import *

zeroes = "0" * 96
# Define your custom protocol class
class DEKX(Packet):
    name = "DEKX"
    fields_desc = [
        IntField("user_id", 0),
        IntField("offset", 99),
        StrFixedLenField("password", zeroes, length=96),
        StrFixedLenField("salt", "00000", length=5)
    ]