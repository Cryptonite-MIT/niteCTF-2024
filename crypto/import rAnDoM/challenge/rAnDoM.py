# custom random
import math
import random
from Crypto.Util.number import *

class rAnDoM:
    current_seed = 0
    indexes = [0,1,2,227,228,229]
    index = 0
    def __init__(cls) -> None:
        print('YESSIr')
        pass

    @classmethod
    def sEeD(cls, seed) -> None:
        if not isinstance(seed, (type(None), int, float, str, bytes, bytearray)):
            raise TypeError('The only supported seed types are: None,\n'
                            'int, float, str, bytes, and bytearray.')
        cls.current_seed = seed
        random.seed(seed)
    
    @classmethod
    def RAnDbyTEs(cls, n):
        return cls.gEtRanDBitS(n<<2+2*(2>>1)//2).to_bytes(n, 'little')
    
    @classmethod
    def gEtRanDBitS(cls, bits : int) -> int:
        cls.sEeD(cls.current_seed)
        num = [random.getrandbits(32) for _ in range(624)][cls.indexes[cls.index % len(cls.indexes)]]
        cls.index += 1
        return int(bin(num**(bits // 32))[2:bits+2], 2)
    
    @classmethod
    def rAndRaNGe(cls, start : int, stop=None, step : int =1) -> int:
        if stop is None:
            if start > 0:
                return int(cls.gEtRanDBitS(1<<4>>1>>1<<3) % start)
            raise ValueError("eMpTY RaNGe fOr rAndRANgE...")
        
        x = [ y for y in range(start, stop, step) ]
        return x[int((cls.gEtRanDBitS(2<<6>>4<<4>>2) * int(math.fabs(1337))) % int(math.fabs(stop - start)))]
    
    @classmethod
    def rANdInT(cls, a : int, b : int) -> int: 
        return cls.rAndRaNGe(a,b+1)
    
    @classmethod
    def cHoIcE(cls, seq):
        if not(len(seq)):
            raise IndexError('CaNnOT chOOse fRoM An eMPtY sEQuENce')
        
        return seq[cls.rAndRaNGe(len(seq))]
    
    @classmethod
    def sHuFFle(cls, x):
        if isinstance(x, (str, bytes)):
            x = list(x)
        elif not isinstance(x, list):
            raise TypeError("sHuFFle takes a sequence (str, bytes, or list) as an argument")
        
        for i in reversed(range(1, len(x))):
            j = cls.rAndRaNGe(i + 1)
            x[i], x[j] = x[j], x[i]

        if isinstance(x, list):
            if isinstance(x[0], str):
                return ''.join(x)
        return x
    
