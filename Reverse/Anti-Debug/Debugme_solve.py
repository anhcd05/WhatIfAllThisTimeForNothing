v11 = []



v11.append(0x277B391F)
v11.append(0x2C252227)
v11.append(0x3F250A14)
v11.append(0x780F147A)
v11.append(0xC0C3E29)
v11.append(0x3F14192E)
v11.append(0x20282239)
v11.append(0x14191431)
v11.append(0x6A253E2D)


flag = ""
for d in v11:
    for b in d.to_bytes(4, "little"):   # 1 số 32-bit → 4 byte, little-endian
        flag += chr(b ^ 0x4B)

print(flag)