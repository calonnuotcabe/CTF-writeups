#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("malloc_testbed")
libc = ELF(elf.runpath + b"/libc.so.6") # elf.libc broke again

gs = f'''
monitor set libthread-db-search-path {elf.runpath.decode()}
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

# Current thread & indices.
cur_thread = 1
indices = [0]

# Select the "malloc" option; send size.
# Returns current thread's chunk index.
def malloc(size):
    global indices
    io.send(b"1")
    io.sendafter(b"size: ", f"{size}".encode())
    io.recvuntil(b"> ")
    indices[cur_thread-1] += 1
    return indices[cur_thread-1] - 1

# Select the "calloc" option; send size.
# Returns current thread's chunk index.
def calloc(size):
    global indices
    io.send(b"2")
    io.sendafter(b"size: ", f"{size}".encode())
    io.recvuntil(b"> ")
    indices[cur_thread-1] += 1
    return indices[cur_thread-1] - 1

# Select the "free" option; send index.
def free(index):
    io.send(b"3")
    io.sendafter(b"index: ", f"{index}".encode())
    io.recvuntil(b"> ")

# Select the "free address" option; send address.
def free_address(address):
    io.send(b"4")
    io.sendafter(b"address: ", f"{address}".encode())
    io.recvuntil(b"> ")

# Select the "edit" option; send index & data.
def edit(index, data):
    io.send(b"5")
    io.sendafter(b"index: ", f"{index}".encode())
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")

# Select the "read" option; send index.
# Return data from read operation.
def read(index):
    io.send(b"6")
    io.sendafter(b"index: ", f"{index}".encode())
    r = io.recvuntil(b"\n1) malloc", drop=True)
    io.recvuntil(b"> ")
    return r

# Select "new thread" option.
def new_thread():
    global indices
    io.send(b"7")
    indices.append(0)
    io.recvuntil(b"> ")

# Select "switch thread" option; send thread number.
def switch_thread(thread):
    global cur_thread
    cur_thread = thread
    io.send(b"8")
    io.sendafter(b"thread: ", f"{thread}".encode())
    io.recvuntil(b"> ")

# Select the "mallopt" option; send parameter then value.
def mallopt(param, val):
    io.send(b"10")
    io.sendafter(b"parameter: ", f"{param}".encode())
    io.sendafter(b"value: ", f"{val}".encode())
    io.recvuntil(b"> ")

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil(b"puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts

io.recvuntil(b"> ")
io.timeout = 0.1

# =============================================================================

# -=-=-= EXAMPLE =-=-=-

# Log some useful info.
info(f"libc is at 0x{libc.address:02x}")

# Request 2 chunks in thread 1.
t1_chunk_A = malloc(0x18)
t1_chunk_B = malloc(0x18)

# Free t1_chunk_A.
free(t1_chunk_A)

# Edit t1_chunk_B.
edit(t1_chunk_B, b"Y"*8)

# Read data from t1_chunk_B.
info(f"reading t1_chunk_B: {read(t1_chunk_B)[:8]}")

# Start a new thread.
new_thread()

# Switch to the new thread (thread 2).
switch_thread(2)

# Request a chunk in thread 2 via calloc().
t2_chunk_A = calloc(0x28)

# Free the chunk we just allocated.
free(t2_chunk_A)

# Change the mmap threshold.
mallopt(5, 0x4000)

# =============================================================================

io.interactive()
