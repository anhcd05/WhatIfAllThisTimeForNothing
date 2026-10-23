




# wanted_value = [72, 184, 100, 57, 120, 74, 97, 85, 53, 89, ]
wanted_value = [100, 57, 120, 74, 97, 85, 53, 89, 112, 77, 
  105, 75, 57, 116, 55, 49, 87, 108, 71]

sbox = "qwertyuiopasdfghjklzxcvbnm0123456789QWERTYUIOPASDFGHJKLZXCVBNM"
# print(len(sbox))
flag = []

chars = []

for i in range(len(wanted_value)):
    for hehe in range(62):
        if sbox[hehe] == chr(wanted_value[i]):
            tmp = hehe - i - 3
            if (tmp <= 0):
                tmp = tmp + 62 
            # print(f"foundMappingPos = {tmp}")
            chars.append(sbox[tmp])
            print(sbox[tmp], end = "")
            break

print(chars)