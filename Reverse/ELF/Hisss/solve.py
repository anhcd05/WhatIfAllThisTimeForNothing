


# enc[7] != enc[5]

# 143 - enc[0] = enc[4] 

# enc[1] ^ enc[3] = 30

# enc[2] * enc[3] = 5610

# enc[1] = 'p'

# enc[6] - enc[8] = -46













enc = [0] * 12
enc[0] = '0' # v
enc[11] = "!" # v
enc[1] = 'p'
enc[9] = chr(109)
enc[10] = '3'
enc[3] = chr(110)
enc[2] = chr(51)

enc[5] = chr(115)
enc[4] = chr(95) # v 

# print(ord(enc[1]) ^ ord(enc[3]))

# print(ord(enc[2]) * ord(enc[3]))
# print(ord(enc[6]) - ord(enc[8]))
# print(ord(enc[6]) ^ ord(enc[7]))
# print(ord(enc[10]) + ord(enc[5]))
# print(ord('n') - ord(enc[9]))

# enc[7] != enc[5]
# enc[7] ^ enc[6] = 64
# enc[6] - enc[8] = -46


tmp = []
for i in range(1, 256):
    for j in range (1, 256):
        if i ^ j == 64 and i != enc[5] and j <= 63 and j >= 30:
            # print(f"{i} {j} SPACE ")
            tmp.append({i, j, j + 46})
            enc[6] = chr(j)
            enc[7] = chr(i)
            enc[8] = chr(j + 46)
            for c in enc:
                print(c, end="")
            print()
