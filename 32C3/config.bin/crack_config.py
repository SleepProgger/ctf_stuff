#
# Bruteforces the config.bin files password and unpack the tar.gz if succesfull.
# This script only works if the "plain_text" is a gzip file (.gz).
# This allows us to only decrypt the first block (16 byte) to verify the password.
#
# Information about the file header and structure found on
# https://heinrichs.io
#
# TODO:
# - Parameter
# - Maybe we can comunicate with _AES even more direct via ctypes ?
#   We need only the first block for the inital check after all.
# - Licence
#

import ctypes
from binascii import hexlify
from hashlib import md5
from Crypto.Cipher import AES, _AES
from time import time as now
import string
from itertools import product as iter_product
from multiprocessing import Process, Queue


THREADS = 2
CHUNK_SIZE = 250000
CONFIG_FILE = "config.bin"
# You may have to change the chars to use.
# Some numbers:
# Possibilities with alphanumeric with 5 chars = ((26*2)+10) ** 5 = 916.132.832
# Possibilities with alphanumeric lower with 5 chars = (26+10) ** 5 = 60.466.176
# My current system makes about 1.000.000 tries per second...
# If you suspect large keyspaces, maybe do it in c ;)
CHARS = string.lowercase + string.digits
# After how many tries should we print the current speed.
STATUS_DELAY = 5000000


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


_aes = _AES.new
def bruteforce_thread(job_queue, result_queue, data, padding):
    while True:
        words = job_queue.get()
        i = 0
        for word in words:
            word = word + padding
            cipher = _aes(word, AES.MODE_ECB)
            uncrypt = cipher.decrypt(data)
            i += 1
            if uncrypt[:3] == "\x1f\x8b\x08":
                result_queue.put((i, word))
        result_queue.put((len(words), None))
    


pad = lambda s: s + (32 - len(s) % 32) * "\x00"
if __name__ == '__main__':   
    # read header
    with open(CONFIG_FILE, "rb") as fd:
        header = fd.read(0x30)
        cipher_text = fd.read()  
    header_struct = Header()
    ctypes.memmove(ctypes.addressof(header_struct), header, 0x30)
    print "Payload_size:", header_struct.payload_size
    print "Header_md5:", hexlify(header_struct.header_md5)
    print "Password_len:", header_struct.password_len
    print "Padding_len:", header_struct.padding_len
    print "Plaintext_md5:", hexlify(header_struct.plaintext_md5)
    # Header checksum
    plain_md5 = "".join(chr(x) for x in header_struct.plaintext_md5)
    header_ = header[0:8]+"\x00"*8+header[16:]
    header_md5 = "".join(chr(x) for x in header_struct.header_md5)
    if md5(header_).digest()[:8] != header_md5:
        print "Invalid header checksum"
        exit()

    # Start bruteforcing
    runs = 0    
    padding = "\x00"*(32-header_struct.password_len)
    join = "".join
    job_queue = Queue(THREADS * 2)
    # We could run into a deadlock here if all process find some valid key and the resul_queue is full.
    # The chances are pretty slime thal'll happen, though... TODO: 
    result_queue = Queue(THREADS*20)
    # Create threads
    threads = [Process(target=bruteforce_thread, args=(job_queue, result_queue, cipher_text[:16], padding)) for x in xrange(THREADS)]
    for thread in threads:
        thread.daemon = True
        thread.start()
    word_iter = iter_product(CHARS, repeat=header_struct.password_len)
    _chunks = tuple(range(CHUNK_SIZE))
    _next_status = STATUS_DELAY
    start_time = now()
    while True:
        words = tuple(join(next(word_iter)) for x in _chunks)
        if len(words) == 0:
            print "No password found."
            break
        job_queue.put(words)
        if runs >= _next_status:
            _next_status += STATUS_DELAY
            start_time_ = now() - start_time
            # This isn't really correct, but good enough
            print "Needed %i seconds for %i words (%d/s). Current word %s" % (
                start_time_, runs, (float(runs)/start_time_), str(words[0])
            )
        while not result_queue.empty():
            processed, word = result_queue.get()
            runs += processed
            if word is None: continue
            # Was it a false positive or the correct password ?
            cipher = _aes(word, AES.MODE_ECB)
            uncrypt = cipher.decrypt(cipher_text)
            data = md5(uncrypt).digest()
            if plain_md5 == data:
                print "[!] Yay found pass '%s'" % word
                uncrypt = uncrypt[:-(header_struct.padding_len)]
                print "... saving to %s.tar.gz" % CONFIG_FILE
                with open(CONFIG_FILE+".tar.gz", "wb") as fd_out:
                    fd_out.write(uncrypt)
                break
        else:
            continue
        break
    start_time = max(0.0001, now() - start_time)
    result_queue.cancel_join_thread()
    job_queue.cancel_join_thread()
    print "Needed %i seconds for %i words (%d/s)" % (start_time, runs, (float(runs)/start_time))
