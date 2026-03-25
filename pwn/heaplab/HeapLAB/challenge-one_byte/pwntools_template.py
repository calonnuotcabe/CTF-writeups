#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("one_byte")
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

# Select the "malloc" option.
# Returns chunk index.
def malloc():
    global index
    io.sendthen(b"> ", b"1")
    index += 1
    return index - 1

# Select the "free" option; send index.
def free(index):
    io.send(b"2")
    io.sendafter(b"index: ", f"{index}".encode())
    io.recvuntil(b"> ")

# Select the "edit" option; send index & data.
def edit(index, data):
    io.send(b"3")
    io.sendafter(b"index: ", f"{index}".encode())
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")

# Select the "read" option; read 0x58 bytes.
def read(index):
    io.send(b"4")
    io.sendafter(b"index: ", f"{index}".encode())
    r = io.recv(0x58)
    io.recvuntil(b"> ")
    return r

io = start()
io.recvuntil(b"> ")
io.timeout = 0.1

# =============================================================================

# =-=-=- EXAMPLE -=-=-=

# Request a chunk.
chunk_A = malloc()

# Edit chunk A.
edit(chunk_A, b"Y"*32)

# Read data from chunk A.
data = read(chunk_A)
info(f"Read from chunk_A:\n{data}")

# Free chunk A.
free(chunk_A)

# Because you haven't leaked a libc address yet, libc.sym.<symbol name>
# will only print a symbol's offset, rather than its actual address.
info(f"offset of puts() from start of GLIBC shared object: 0x{libc.sym.puts:02x}")

# Once you've leaked an address, e.g. the printf() function, use:
# libc.address = <leaked printf address> - libc.sym.printf
# to correctly set your libc base address to its runtime address. Now future calls
# to libc.sym will use the symbol's actual address rather than its offset.

# =============================================================================

io.interactive()
