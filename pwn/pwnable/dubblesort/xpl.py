from pwn import *

elf = context.binary = ELF("./dubblesort")

gs = '''
start
'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

p = start()

def name():
    p.sendafter(b"What your name :" ,b"hehe")
def number():
    p.sendafter(b",How many numbers do you what to sort :", p64(0xdeadbeef))
def main():
    name()
    number()

if __name__ == "__main__":
    main()

