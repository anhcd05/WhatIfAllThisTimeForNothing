



key = [0x53, 0x75, 0x50, 0x33, 0x52, 0x53 , 0x61, 0x46, 0x65, 0x4b, 0x33, 0x59]

with open("flag.enc", "rb") as f:
    data = f.read()

res = bytearray()

for cnt in range(0, len(data), 4):
    v3_new = int.from_bytes(data[cnt:cnt+2], "little")
    v4_new = int.from_bytes(data[cnt+2:cnt+4], "little")
    # print(v3_new)
    # print(v4_new)

    v3_old = -1
    v4_old = -1

    for i in range(2, -1, -1):
        sub_key_1 = (key[4 * i] | key[4 * i + 1] << 8) & 0xFFFF
        sub_key_2 = (key[4 * i + 2] | key[4 * i + 3] << 8) & 0xFFFF
        # print(sub_key_1)
        # print(sub_key_2)

        v4_old = ((((v3_new ^ sub_key_2) >> 7) & 0xFFFF) | (((v3_new ^ sub_key_2) << 9) & 0xFFFF)) & 0xFFFF
        v3_old = (((((v4_new ^ sub_key_1) - v4_old) & 0xFFFF) >> 7) & 0xFFFF) | (((((v4_new ^ sub_key_1) - v4_old) & 0xFFFF) << 9) & 0xFFFF)

        v4_new = v4_old
        v3_new = v3_old
        # print(v3_old)
        # print(v4_old)
    res.extend(v3_old.to_bytes(2, "little"))
    res.extend(v4_old.to_bytes(2, "little"))
    # print(v4_old)
    # print(v3_old)
print(res)





