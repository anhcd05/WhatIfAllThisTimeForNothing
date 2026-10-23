


key = [0xDE, 0xAD, 0xBE, 0xEF]

with open("encrypted", "rb") as f:
    enc = f.read()


# print(enc)
plain = bytearray()
for i in range (0, len(enc)):
    tmp = ((enc[i] - 19) ^ key[i % 4]) & 0xFF
    # print(tmp)
    plain.append(tmp)



with open("flag.png", "wb") as flag:
    flag.write(plain)

