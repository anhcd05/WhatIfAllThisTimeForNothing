




with open("logs") as f:
    enc = f.read()


for i in range(len(enc)):
    print(chr(ord(enc[i]) ^ 0x19), end = "")




