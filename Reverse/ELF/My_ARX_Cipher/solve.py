

# v4_new = 0x345a
# v3_new = 0xdf79
# key = "SuP3RSaFeK3Y"
key = [0x53, 0x75,  0x50, 0x33, 0x52, 0x53,  0x61, 0x46,  0x65, 0x4b, 0x33, 0x59]

with open("flag.enc", "rb") as f:
    enc = f.read()

#v4_enc = val.to_bytes(2, "little")
# print(v4_enc)

res = bytearray()

for cnt in range(0, len(enc), 4):
    v4_new = int.from_bytes(enc[cnt+2:cnt+4], "little")
    v3_new = int.from_bytes(enc[cnt+0:cnt+2], "little")
    v3_old = -1
    v4_old = -1

    for i in range(2, -1, -1):
        v5 = v4_new
        sub_key_1 = key[4 * i] | (key[4 * i + 1] << 8)
        sub_key_2 = key[4 * i + 2] | (key[4 * i + 3] << 8)


        v4_old = ( (((v3_new ^ sub_key_2) >> 7) & 0xFFFF ) |( ((v3_new ^ sub_key_2) << 9) & 0xFFFF ) ) & 0xFFFF 
        v3_old = (((((((v5 ^ sub_key_1) & 0xFFFF) - v4_old) & 0xFFFF) >> 7) & 0xFFFF)  | ((((((v5 ^ sub_key_1) & 0xFFFF) - v4_old) & 0xFFFF) << 9) & 0xFFFF) ) & 0xFFFF 

        v3_new = v3_old
        v4_new = v4_old
        # print(hex(v3_old))
        # print(hex(v4_old))
    res.extend(v3_old.to_bytes(2, "little"))
    res.extend(v4_old.to_bytes(2, "little"))
print(res)
