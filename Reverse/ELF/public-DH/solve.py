




def decryptRSA(ciphertext, d, N):
    plaintext = pow(ciphertext, d, N)
    return plaintext



with open("out.bin", "rb") as f:
    cipher = f.read()

# print(cipher)


N =  4271010253
e = 201326609

p = 65287 
q = 65419

phi = (p - 1) * (q - 1)
plain = []
# print(phi) = 4270879548

import math

# if (math.gcd(e, phi) == 1):
#     print("WOWOWOW")

d = pow(e, -1, phi)
# print(d) = 1278822490

for i in range(0, len(cipher), 4):
    if cipher[i] != 0:
        # print(cipher[i], cipher[i + 1], cipher[i + 2], cipher[i + 3])

        # for j in range (0, 4):
        # print(cipher[i], cipher[i + 1], cipher[i + 2], cipher[i + 3])
        ciphertext_block_4_bytes = str(cipher[i]) + str(cipher[i + 1]) + str(cipher[i + 2]) + str(cipher[i + 3]) 
        # print(ciphertext_block_4_bytes)


        print(f"DEBUG HERE {decryptRSA(int(ciphertext_block_4_bytes), d, N)}")
        # print(plain)



# print(plain)

