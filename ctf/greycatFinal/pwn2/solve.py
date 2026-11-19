from pwn import *

elf = ELF("./chall_patched")
context.log_level = "debug"

gs = """
c
"""

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)
p = start()
p.interactive()