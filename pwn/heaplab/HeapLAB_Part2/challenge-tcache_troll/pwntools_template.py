#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("tcache_troll")
libc = ELF(elf.runpath + b"/libc.so.6") # elf.libc broke again

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

# Index of allocated chunks.
index = 0

# Select the "malloc" option; send size & data.
# Returns chunk index.
def malloc(size, data):
    global index
    io.send(b"1")
    io.sendafter(b"size: ", f"{size}".encode())
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")
    index += 1
    return index - 1

# Select the "free" option; send index.
def free(index):
    io.send(b"2")
    io.sendafter(b"index: ", f"{index}".encode())
    io.recvuntil(b"> ")

# Select the "read" option.
# Returns 8 bytes.
def read(index):
    io.send(b"3")
    io.sendafter(b"index: ", f"{index}".encode())
    r = io.recv(8)
    io.recvuntil(b"> ")
    return r

io = start()
io.recvuntil(b"> ")
io.timeout = 0.1

# =============================================================================

# =-=-=- EXAMPLE -=-=-=

# Request a 0x410-sized chunk and fill it with data.
chunk_A = malloc(0x408, b"A"*0x408)

# Read the 1st quadword of chunk A's user data.
info(f"{read(chunk_A)}")

# Free chunk A.
free(chunk_A)

# =============================================================================

io.interactive()
