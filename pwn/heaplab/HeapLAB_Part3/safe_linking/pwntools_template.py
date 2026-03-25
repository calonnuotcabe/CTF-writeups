#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("safe_linking")
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
indices = [0, 0, 0, 0]

# Select the "malloc" option; send size.
# Returns current thread's chunk index.
def malloc(size):
    global indices
    io.send(b"1")
    io.sendafter(b"size: ", f"{size}".encode())
    io.recvuntil(b"> ")
    indices[cur_thread-1] += 1
    return indices[cur_thread-1] - 1

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

# Select "new thread" option.
def new_thread():
    io.send(b"4")
    io.recvuntil(b"> ")

# Select "switch thread" option; send thread number.
def switch_thread(thread):
    global cur_thread
    cur_thread = thread
    io.send(b"5")
    io.sendafter(b"thread: ", f"{thread}".encode())
    io.recvuntil(b"> ")

io = start()
io.recvuntil(b"> ")
io.timeout = 0.1

# =============================================================================

# Create new threads.
new_thread() # Thread 2.
new_thread() # Thread 3.

# Request 2 chunks in thread 1.
t1_A = malloc(0x18)
t1_B = malloc(0x18)

# Switch to thread 2 & allocate to create a 2nd arena.
switch_thread(2)
t2_A = malloc(0x18)

# Switch to thread 3 & allocate to join the main arena.
switch_thread(3)
t3_A = malloc(0x18)

# =============================================================================

io.interactive()
