







key = [7,   7,  10,   5,  15,  13,   8,   6,  14,  11,  16,  10,   9]

print(len(key))


# tmp = "_this_is_sample_flag_"
# print(len(tmp))

rev1 = [52, 50, 99, 104, 127, 127, 120, 89, 122, 84, 121, 107, 124, 115, 52, 102, 104, 63, 99,  ]
print(len(rev1))

# inverse_do_math_2
for i in range(len(rev1)):
    rev1[i] = rev1[i] ^ key[i % len(key)]

# # inverse_do_math_1
# for i in range (len(key)):
#     tmp = rev1[i]
#     rev1[i] = rev1[key[i]]
#     rev1[key[i]] = tmp

# ch4ng3_fla9_wi7h_3a5y

for i in range(len(key) - 1, -1, -1):
    tmp = rev1[0]
    rev1[0] = rev1[key[i]]
    rev1[key[i]] = tmp   

for i in range(len(rev1)):
    print(chr(rev1[i]), end="")







