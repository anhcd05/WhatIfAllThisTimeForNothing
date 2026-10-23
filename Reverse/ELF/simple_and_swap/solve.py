


from pwn import *

enc = [111, 13, 110, 128, 16, 34, 244, 112, 213, 82, 
  131, 116, 37, 22, 71, 56]

out = bytearray()

for i in range(len(enc)):
    tmp = (enc[i] - i) ^ 0x5A
    tmp = ((tmp >> 4) | (tmp << 4)) & 0xFF
    # print(chr(tmp), end = " ")
    out.append(tmp)
# print(out)
# p = process("./chall")
p = remote("host3.dreamhack.games", 18022)
p.sendline(out)
p.interactive()



