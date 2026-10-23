


import requests

HOST1 = "http://host3.dreamhack.games:10041/step1"

PARAMS1 = {
    "param":"getget",
    "param2":"rerequest"
}

step1 = requests.get(url=HOST1, params=PARAMS1, allow_redirects=False)


import re
# \d đại diện cho một ký tự số bất kỳ từ 0 - 0
# dấu + là số nhiều (từ 1 trở lên) 
step1_num = re.findall(r"prev_step_num=(\w+)", step1.text)[0]

HOST2 = "http://host3.dreamhack.games:10041/step2"

PARAMS2 = {
    "prev_step_num":step1_num
}

step2 = requests.get(url=HOST2, params=PARAMS2)

step2_num = re.findall(r"value=\"(\w+)\"", step2.text)[0]
# print(step2.text)
# print(f"FOUND FOUND FOUND {step2_num}")


PARAMS_FLAG = {
    "check":step2_num,
    "param":"pooost",
    "param2":"requeeest"
}

HOST_FLAG = "http://host3.dreamhack.games:10041/flag"

request_flag = requests.post(url=HOST_FLAG, data=PARAMS_FLAG)
print(request_flag.text)
