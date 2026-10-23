from pwn import *
import re

# p = process("./prob")
p = remote("host3.dreamhack.games", 22495)
for z in range(10):
    line = p.recvuntil(b"[INFO]")
    # print(line)
    wanted_line = p.recvline()
    # print(wanted_line)


    wanted_value = re.findall(rb"\d+", wanted_line)
    converted = []
    for num in wanted_value:
        num2 = int(num)
        converted.append(num2)
        # print(num2, end=" ")

    # print(wanted_value)

    ptr = converted[0] << 48 | converted[1] | converted[2] << 8 | converted[3] << 16 | converted[4] << 24 | converted[5] << 32 | converted[6] << 40

    # print(ptr)

    bin_ptr = bin(ptr)

    res = "A"

    for i in range(3, len(bin_ptr)):
        if bin_ptr[i] == "1":
            res = res + "BA"
        else:
            res = res + "B"

    res = res.encode()
    # print(res)
    p.sendline(res)
p.interactive()

