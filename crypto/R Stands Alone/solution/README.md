# R Stands Alone - solution

First of all. Realised this during the CTF and heavy apologies for it :
1. the gen_keys() function has 512 bit primes, not 128 bit. Did clarify this in any tickets raised, and the crypto channel on the discord. apologies for any discrepencies.
2. This challenge was flawed and not thought out well, as it had a heavy unintended solve. `r` being much larger than `p` `q` resulted in `phi = (r-1)` simply. Making the solve much easier than the intended.


## Intended solve :

We have basic rsa with `N = p * q * r` \
but the players have only been provided `r` and `ct` and `e` \
going through `chal.py` you see the function to generate the primes 
```python
def gen_keys():
    while True:
        a = getPrime(512)
        b = getPrime(512)
        A = a+b
        B = a-b 
        
        p = ((17*A*A*A) - (15*B*B*B) - (45*A*A*B) + (51*A*B*B)) // 8

        if isPrime(p) :
            return a, b, p
```

Here we can see that r is being generated via the equation \
```py
r = ((17*A*A*A) - (15*B*B*B) - (45*A*A*B) + (51*A*B*B)) // 8
```
where, \
 `A = p+q` \
 `B = p-q`

putting the values of `A` `B` in above equation it simplifies to : \
` r = p**3 + 16q**3 `

Mod `r` both sides

` 0 = p**3 + 16q**3`  (mod r) \
` p**3 = -16 q**3`    (mod r) \

Cube root both sides \
`p = x q  (mod r)`
where `x = cube_root(-16) in ring r`

```
p = x q           (mod r)
p = xq - kr
```

we can construct vectors such that : 
```
q[x, 1] - k[r, 0] = [qx - kr, q]
q[x, 1] - k[r, 0] = [ p, q ]
```

Thus, reduce the lattice `[x, 1] [r, 0]` \
where `x = cube_root(-16) in ring r` \
you will get `p, q`

Now you have `p, q, r` \
`e = 65537` \
Normal rsa decryption from here

### `nite{7h3_Latt1c3_kn0ws_Ur_Pr1m3s_very_vvery_v3Ry_w3LLL}`
