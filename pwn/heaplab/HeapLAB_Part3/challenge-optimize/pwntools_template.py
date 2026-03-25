#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("optimize")
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

# Select the "malloc" option; send size.
# Return chunk index.
def malloc(size):
    global index
    io.send(b"1")
    io.sendafter(b"size: ", f"{size}".encode())
    io.recvuntil(b"> ")
    index += 1
    return index - 1

# Select the "free" option; send index.
def free(index):
    io.send(b"2")
    io.sendafter(b"index: ", f"{index}".encode())
    io.recvuntil(b"> ")

# Select the "edit" option; send index & data.
def edit(index, data, discard=True):
    io.send(b"3")
    io.sendafter(b"index: ", f"{index}".encode())
    io.sendafter(b"data: ", data)
    if discard: io.recvuntil(b"> ")

# Select the "optimize" option; send value.
def optimize(mxfast):
    io.send(b"4")
    io.sendafter(b"size: ", f"{mxfast}".encode())
    io.recvuntil(b"> ")

io = start()
io.recvuntil(b"> ")
io.timeout = 0.1

# =============================================================================

# =-=-=- EXAMPLE -=-=-=

# Request an 0x80-sized chunk followed by a guard chunk.
chunk_A = malloc(0x78)
malloc(0x18)

# Write data into chunk_A.
edit(chunk_A, b"A"*0x78)

# Set global_max_fast to 0x70.
optimize(0x70)

# Free "chunk_A".
free(chunk_A)

# If the tcache weren't in use, chunk_A would end up in the unsortedbin.
# You're probably better off experimenting with mallopt()'s M_MXFAST
# parameter in the malloc testbed where you can disable the tcache.

# =============================================================================

io.interactive()
