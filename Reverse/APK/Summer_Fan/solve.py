




def gen(i):
    return (pow(i, 3) % 256) ^ (ord(key[len(key) - ((i % len(key)) + 1)]))

enc = [220, 211, 180, 230, 192, 22, 341, 220, 227, 341, 139, 163, 355, 293, 333, 196, 142, 216, 376, 133, 248, 26, 342, 378, 231, 149, 145, 173, 185, 1, 10, 198]

key = "hot_hot_summmerr"




for i in range(0, len(enc)):
    tmp = (enc[i] ^ ord(key[i % len(key)])) - gen(i)
    print(chr(tmp), end = "")


