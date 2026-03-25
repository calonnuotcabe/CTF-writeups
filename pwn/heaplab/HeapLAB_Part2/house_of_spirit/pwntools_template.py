#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("house_of_spirit")
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

# Select the "malloc" option; send size, data & chunk name.
# Returns chunk index.
def malloc(size, data, name):
    global index
    io.send(b"1")
    io.sendafter(b"size: ", f"{size}".encode())
    io.sendafter(b"data: ", data)
    io.sendafter(b"name: ", name)
    io.recvuntil(b"> ")
    index += 1
    return index - 1

# Select the "free" option; send the index.
def free(index):
    io.send(b"2")
    io.sendafter(b"index: ", f"{index}".encode())
    io.recvuntil(b"> ")

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil(b"puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts

# This binary leaks the heap start address.
io.recvuntil(b"heap @ ")
heap = int(io.recvline(), 16)
io.timeout = 0.1

# =============================================================================

# =-=-=- EXAMPLE -=-=-=

# Set the "age" field.
age = 0x6f
io.sendafter(b"age: ", f"{age}".encode())

# Set the "username" field.
username = b"George"
io.sendafter(b"username: ", username)
io.recvuntil(b"> ")

# Request a 0x20-sized chunk.
# Fill it with data and name it.
name = b"A"*8
chunk_A = malloc(0x18, b"Y"*0x18, name)

# Free the chunk.
free(chunk_A)

# =============================================================================

io.interactive()
