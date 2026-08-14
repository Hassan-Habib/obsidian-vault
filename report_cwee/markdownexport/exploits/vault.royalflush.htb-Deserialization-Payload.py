#!/usr/bin/env python3  
import base64  
import sys  
from Crypto.Cipher import AES  
from Crypto.Util.Padding import pad  
  
KEY = b"f3d9aa53-c08d-43"  
IV = b"5ac8083e-8ff6-43"  
  
payload_b64 = open(sys.argv[1], "r").read().strip()  
plaintext = base64.b64decode(payload_b64)  
  
cipher = AES.new(KEY, AES.MODE_CBC, IV)  
ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))  
print(base64.b64encode(ciphertext).decode())