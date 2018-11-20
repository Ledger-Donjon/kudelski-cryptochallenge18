import numpy as np
import requests
from Crypto.Cipher import AES
from binascii import hexlify

def list2num(x):
   res = 0
   for i in range(16):
      res |= ((int(x[i]) & 0xff) << (120 - 8 * i ))
   return(res)

def padhexa(s):
    return '0x' + s[2:].zfill(8)

candidate_skey0 = [[1 for i in range(256)] for j in range(16)]

def key_found():
   s = [ sum(candidate_skey0[i]) for i in range(16) ]
   for i in range(16):
      if sum(candidate_skey0[i]) != 1:
         return False
   return True; 

def update_candidates(idx, plaintext):
   for i in range(16):
      for k in range(256):
         if plaintext[i] ^ k == idx:
            candidate_skey0[i][k] = 0
         

file = open("faults", "r")

for flt in file.readlines():
   ans = flt.split()
   datain = [0 for i in range(16)];
   if int(ans[0]) == 2:
      hexpT = ans[1]
      for i in range(16):
         datain[i] = int('0x' + hexpT[i*2:i*2+2], 16)
      idx_sbox = int(ans[2])
      update_candidates(idx_sbox,datain)
      if key_found():
         break

key = [0 for i in range(16)]

for i in range(16):
   for j in range(256):
      if candidate_skey0[i][j] == 1:
         key[i] = j

keyHex = key[0]
for i in range(1,16):
   keyHex <<= 8
   keyHex |= key[i]

print("Key is : 0x%x" % keyHex)

encrypted_flag = 0x0ef338db85b477124d36decb9452fb1d
aes = AES.new(keyHex.to_bytes(16,'big'), AES.MODE_ECB)
print(bytes(aes.decrypt(encrypted_flag.to_bytes(16,'big'))))
