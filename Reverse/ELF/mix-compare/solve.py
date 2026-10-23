


enc = [57,   0,   0,   0, 155, 255, 255, 255,  44,   0, 
    0,   0, 198,   0,   0,   0,  89,   0,   0,   0, 
   88,   0,   0,   0,  57,   0,   0,   0, 171,   0, 
    0,   0, 206, 255, 255, 255, 198,   0,   0,   0, 
  140,   1,   0,   0, 144,   1,   0,   0, 218, 255, 
  255, 255, 115,   0,   0,   0,  82,   0,   0,   0, 
  102,   0,   0,   0]

print(len(enc))

vals = []

for i in range(0, len(enc), 4):
    vals.append(int.from_bytes(enc[i:i+4], "little"))


plaintext = []
plaintext.append(vals[0] - 9)
plaintext.append(~vals[1] % 256)
plaintext.append(vals[2] + 4)
plaintext.append(vals[3] / 2)
plaintext.append(vals[4] - 34)
plaintext.append(vals[5] - 40)
plaintext.append(vals[6] + 40)
plaintext.append(vals[7] / 3)
plaintext.append(~vals[8] % 256)
plaintext.append(vals[9] / 2)
plaintext.append(vals[10] / 4)
plaintext.append(vals[11] / 4)
plaintext.append((19 - vals[12]) % 256)
plaintext.append(vals[13] - 17)
plaintext.append(vals[14] - 30)
plaintext.append(vals[15])


# print(plaintext)
for i in range(len(plaintext)):
    print(chr(int(plaintext[i] % 256)), end = "")



