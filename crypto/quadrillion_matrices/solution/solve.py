from sage.all import *
from Crypto.Util.number import *

with open('out', 'r') as f:
    p = eval(f.readline())
    out = eval(f.readline())

flag_bits = ""
for i in out:
    A = Matrix(GF(p), i)
    symbol = A**((p-1)//2)
    if(symbol == identity_matrix(symbol.nrows())):
        flag_bits += '0'
    else:
        flag_bits += '1'

print(long_to_bytes(int(flag_bits, 2)))
