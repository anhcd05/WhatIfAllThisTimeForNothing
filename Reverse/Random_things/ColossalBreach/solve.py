

from pwn import *


p = remote("154.57.164.64", 33478)

p.recvuntil(b"module's author?")
p.sendline(b"0xEr3n")

p.recvuntil(b"eyboard events?")
p.sendline(b"register_keyboard_notifier")

p.recvuntil(b"es to strings?")
p.sendline(b"keycode_to_string")

p.recvuntil(b"full path")
p.sendline(b"/sys/kernel/debug/spyyy/keys")

p.recvuntil(b"when imported?")
p.sendline(b"w00tw00t")

p.recvuntil(b"uscate the keys?")
p.sendline(b"0x19")

p.recvuntil(b"entered for 'adam'?")
p.sendline(b"supers3cur3passw0rd")

p.interactive(b"")