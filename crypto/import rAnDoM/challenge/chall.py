from rAnDoM import *
import random
from Crypto.Util.number import *

flag = b"nite{REDACTED}"
chunks = [bytes_to_long(flag[i:i+4]) for i in range(0, len(flag), 4)]

yap = ""
for i in chunks:
    rAnDoM.sEeD(i)
    yap += hex(rAnDoM.gEtRanDBitS(32))
    yap += hex(rAnDoM.gEtRanDBitS(32))
    yap += hex(rAnDoM.gEtRanDBitS(32))
    yap += hex(rAnDoM.gEtRanDBitS(32))
    yap += hex(rAnDoM.gEtRanDBitS(32))
    yap += hex(rAnDoM.gEtRanDBitS(32))

print("WHAT IS BRO YAPPING ?!!")
print(f"\nbro :\n{yap}")
print("\nBRO WHAT ??!?!")
