



from pwn import *

p = process("./chall")
# p = ...

p.recvuntil(b"Random number:")
line = p.recvline()
print(line)

import re
num = re.findall(rb"0x\S+", line)
# num = int.from_bytes(num[0])
print(num[0])

wanted = 0xa0b4c1d7
wanted_rev = int(f"{wanted:08x}"[::-1], 16)

print(wanted_rev)
xor_key = int(num[0], 16)
val = xor_key ^ wanted_rev
print(val)


p.sendline(str(val).encode())

tmp = p.recvline()
print(tmp)

tmp = p.recvline()
print(tmp)

tmp = p.recvline()
print(tmp)









