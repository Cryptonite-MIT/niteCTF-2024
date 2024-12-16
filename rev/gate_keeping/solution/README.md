# Gate Keeping - Solution

The name and description are absolutely irrelevant.

The challenge is a virtual machine. The challenge is taken inspiration from pwn.college's Yan85 series.

The VM challenge's opcode takes an input, circular right shifts it by 2, xor's it with a specific string, circular left shifts it by 1, xor's it again with a specific string, and then compares with a ciphertext.

Well just reverse the process (omg reverse engineering)

The major things to watch out is

1. The NOR gate is a universal gate, which in this VM is combined to form an XOR gate.
2. Circular right shift and left shift both are 8-bit because all the registers (except the instruction pointer) are 8-bit. `pwn.ror()` and `pwn.rol()` work on 64-bit values.

The main decryption part can be done as below:

```py
def custom_rol(value, n):
    value &= 0xff
    n &= 0xff
    return ((value << n) | (value >> (8 - n))) & 0xff

def custom_ror(value, n):
    value &= 0xff
    n &= 0xff
    return ((value >> n) | (value << (8 - n))) & 0xff

enc = [0x5f, 0xc, 0xc3, 0x88, 0xc6, 0x8a, 0xe4, 0x6, 0xd1, 0x3a, 0x79, 0x8f, 0xd1, 0x8, 0x5c, 0x12, 0xfc, 0x97, 0x74, 0x17, 0xf5, 0xb3, 0xde, 0x84, 0xd9, 0xcc, 0xad, 0xcd, 0xba, 0xe9, 0x25, 0x49, 0x80, 0x6e]


for i in range(len(enc)):
    enc[i] ^= (i + 0xa7) % 255
    enc[i] = custom_rol(enc[i], 2) % 256
    enc[i] ^= (i + 0x3f)
    enc[i] = custom_ror(enc[i], 1)

print(enc.decode())
```

**Flag:** **`nite{n0r_15_a_un1v3r54l_g4t3_to0!}`**
