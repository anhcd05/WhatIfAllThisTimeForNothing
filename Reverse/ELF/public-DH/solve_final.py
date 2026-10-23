




def decryptRSA(c, d, N):
    return pow(c, d, N)



with open ("out.bin", "rb") as output:
    ciphertext_bytes = output.read()

N = 4271010253
e = 201326609
p = 65287
q = 65419

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

# flag_enc = enc_rsa(flag_plain: *(unsigned int *)&s[4 * i], a2: e, a3: N);

# tmp = int.from_bytes(ciphertext_bytes[0:4])
# print(tmp)
# print(len(ciphertext_bytes))



for i in range(0, len(ciphertext_bytes), 8):
    # print(int.from_bytes(ciphertext_bytes[i:i+8], "little"))
    block = int.from_bytes(ciphertext_bytes[i:i+8], "little")
    plaintext = decryptRSA(block, d, N).to_bytes(4, "little")
    print(plaintext.decode("ascii"), end = "")
    
