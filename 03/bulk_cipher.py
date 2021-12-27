import random
import string
import os

BLOCK_SIZE = 16

key = os.urandom(BLOCK_SIZE)
iv = os.urandom(BLOCK_SIZE)
msg = ''.join(random.choice(string.ascii_lowercase) for i in range(1024))
assert decrypt(key, iv, encrypt(key, iv, msg)) == msg

