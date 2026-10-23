
import hashlib



wanted_hash = "d974e538cf501afdfc3986041c5a3993"
CHARSET = "ABCDEFabcdef0123456789"

# li_CHARSET = list(CHARSET)
# print(li_CHARSET)


for a in CHARSET:
    for b in CHARSET:
        for c in CHARSET:
            for d in CHARSET:
                for e in CHARSET:
                    for f in CHARSET:
                        tmp = a + b + c + d + e + f
                        # s = "GeeksforGeeks"
                        hashValue = hashlib.md5(tmp.encode())
                        # print(hashValue.hexdigest())
                        # print(hashValue.hexdigest())
                        if hashValue.hexdigest() == wanted_hash:
                            print(tmp)
                            break