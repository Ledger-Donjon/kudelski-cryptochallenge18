import numpy as np
import requests


while True:
   datain = [np.random.randint(255) for i in range(16)];
   strHex = ""
   for i in range(16):
      strHex += "%0.2X" % datain[i]
   req = requests.post("https://cryptochall.ks.kgc.io/chall3/encrypt",
                            json={"data": strHex})
   ans = req.text
   if 'Unavailable' in ans:
      continue
   
   if 'index' in ans and 'Ciphertext' in ans:
      r = [int(s) for s in ans.split() if s.isdigit()]
      print(1, strHex, r[0])
   elif 'index' in ans and 'Ciphertext' not in ans:
      r = [int(s) for s in ans.split() if s.isdigit()]
      print(2, strHex, r[0],ans.split()[-1].rstrip())
   else:
      print(0, strHex, ans.rstrip())

    
