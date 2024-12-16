from Crypto.Util.number import *
from secret import gen_matrix
from sage.all import *
import random

p = getPrime(256)

with open('flag', 'rb') as f:
    flag = bin(bytes_to_long(f.read()))[2:]

out = []

for i in flag:
    M = gen_matrix(p)
    out.append( list((M**(random.randrange(3+int(i), p, 2))) * (M**(random.randrange(3, p, 2)))) )

with open('out', 'w') as f:
    f.write(str(p) + '\n')
    f.write(str(out))
