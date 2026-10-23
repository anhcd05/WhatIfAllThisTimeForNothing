
import re
from pwn import *
p = remote("host3.dreamhack.games", 19479)

p.recvuntil("Random number:")

num = p.recvline()
print(num)

wanted_val = 0xa0b4c1d7
rev_wanted_val = int(f"{wanted_val:08x}"[::-1], 16)

xor_key = int(num.strip(), 16)
print(xor_key)



p.sendline(str(xor_key ^ rev_wanted_val).encode())
p.interactive()






