import ctypes
from binascii import hexlify
from hashlib import md5
from Crypto.Cipher import AES
from time import time as now
import string
from itertools import product as iter_product

class Header(ctypes.BigEndianStructure):
    _fields_ = [
                ("magic", ctypes.ARRAY(ctypes.c_char, 4)),
                ("payload_size", ctypes.c_uint32),
                ("header_md5", ctypes.ARRAY(ctypes.c_ubyte, 8)),
                ("etl", ctypes.ARRAY(ctypes.c_uint8, 7)), # always zero
                ("unused_1", ctypes.c_char),
                ("password_len", ctypes.c_uint16),
                ("padding_len", ctypes.c_uint16),
                ("unused_2", ctypes.ARRAY(ctypes.c_ubyte, 4)),
                ("plaintext_md5", ctypes.ARRAY(ctypes.c_ubyte, 16))
                ]

pad = lambda s: s + (32 - len(s) % 32) * "\x00"
if __name__ == '__main__':
    config_file = "config.bin"
    # You may have to change the chars to check
    chars = string.lowercase
    
    # read header
    with open(config_file, "rb") as fd:
        header = fd.read(0x30)
        cipher_text = fd.read()  
    header_struct = Header()
    foo = ctypes.memmove(ctypes.addressof(header_struct), header, 0x30)
    print "Payload_size:", header_struct.payload_size
    print "Header_md5:", hexlify(header_struct.header_md5)
    print "Password_len:", header_struct.password_len
    print "Padding_len:", header_struct.padding_len
    # Header checksum
    header_ = header[0:8]+"\x00"*8+header[16:]
    header_md5 = "".join(chr(x) for x in header_struct.header_md5)
    if md5(header_).digest()[:8] != header_md5:
        print "Invalid header checksum"
        exit()

    # Start bruteforcing
    runs = 0    
    char_len = len(chars)
    padding = "\x00"*(32-header_struct.password_len)
    start_time = now()
    for word in iter_product(chars, repeat=5):
        word = "".join(word) + padding # This could be done faster
        if runs % 1000000 == 0 and runs > 0:
            start_time_ = now() - start_time
            print "Needed %i seconds for %i words (%d/s). Current word %s" % (
                start_time_, runs, (float(runs)/start_time_), word
            ) 
        runs += 1
        cipher = AES.new(key=word, mode=AES.MODE_ECB)
        # Only decrypt the first block
        uncrypt = cipher.decrypt(cipher_text[:16])
        if uncrypt[:3] != "\x1f\x8b\x08":
            continue                
        # We should compare the plaintext md5 with one from the header here,
        # but somehow i messed this up, so lets just do it the zgly way and
        # assume the archive name always starts with "config".
        if "config" in uncrypt:
            print "[!] Yay found pass '%s'" % word
            uncrypt += cipher.decrypt(cipher_text[16:])
            uncrypt = uncrypt[:-(header_struct.padding_len)]
            print "... saving to %s.tar.gz" % config_file
            with open(config_file+".tar.gz", "wb") as fd_out:
                fd_out.write(uncrypt)                
            break
    else:
        print "No password found"
    start_time = max(0.01, now() - start_time)
    print "Needed %i seconds for %i words (%d/s)" % (start_time, runs, (float(runs)/start_time))
