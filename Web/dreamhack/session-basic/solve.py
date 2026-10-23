


import requests

HOST = "http://host3.dreamhack.games:16965/"

HEADERS = {
    "Cookie":"sessionid=0bab041ee0bdd2bb52bb6ef065ae64246ad0621cd1bef729779f34b013557e03"
}

r = requests.get(url=HOST, headers=HEADERS)

print(r.text)
