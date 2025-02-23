from scapy.all import *

sha_256_zeroes = "0" * 256
# Define your custom protocol class
class DEKX(Packet):
    name = "DEKX"
    fields_desc = [
        IntField("user_id", 0),
        IntField("offset", 259),
        StrFixedLenField("password", sha_256_zeroes, length=256),
        StrFixedLenField("salt", sha_256_zeroes, length=256),
        StrFixedLenField("datetime", sha_256_zeroes, length=256)
    ]