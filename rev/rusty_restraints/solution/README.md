# Rusty Restraints Solution

Yeah so to solve this, launch the binary on Ghidra(looks cleaner). You may wanna use the latest version of Ghidra as it arranges the encrypted AES values properly rather than appending all of them in the previous versions.

It's a stripped rust binary. You'll find the key and iv for the encrypted values infront of you in the main function. Now if you simply write a script to decrypt it, you'll get a padding error thrown at you. Going back to the binary, if you look around a bit, you'll realize that the encrypted values might be initially handled as a u32 values.

u16 supports values from 0 to 65,535 (0xFFFF) and u32 supports values from 0 to 4,294,967,295 (0xFFFFFFFF)

So once you realize that, you can decrypt it easily and the last 4 bytes define the PKCS7 padding.

```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii

def decrypt_hex(encrypted_hex: str, key: bytes, iv: bytes) -> int:
    encrypted_bytes = bytes.fromhex(encrypted_hex)

    cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)

    result = int.from_bytes(decrypted_bytes[-4:], byteorder='big')

    return result


def main():
    key = b"amzpqwestwgckshy"
    iv = b"vsjwpokqweqofbmy"

    encrypted_values = [
    "28ce5c78e2af45d7d9998993b52a815b", "c927a4a41a8f263a64727c4924db3b80",
    "9b61a79e96b2900187109e7dc2a9b80a", "b1d4e8fb2b816f8b65dc6bdfda411dd6",
    "fb25c9f8b411ad2f63c1e03edfbc72bf", "963eff5569548b3dbe2158522ae26722",
    "f4f5ee5502dd8fb2561567f052693328", "d2c22194d9fb9acacd87e4127b7ad0f7",
    "2a21a1486b6c9a36668f1425e90de7af", "e87d84083df0945a86374fdc5ec76224",
    "2430e3ba14543ccb13ee315beb88e903", "6eee3efe14a46d4053b8d24bd29abd4b",
    "60321b6ba267d8f6d05e98564dfd9545", "c8731ed736fb7911ac0b2804021a0f16",
    "96f4d52c469abe8a8d278f0c4499a09a", "5e05380a70c9bebbe009a282b2a19657",
    "c0e906fe203feca4e4b3c29439d54ee3", "e3511cd9a041b5e198468e37d1920262",
    "cf400dbeedb9f6e6a55e39378a42c58c", "c9d75442e56447881203d1ff1e43fe39",
    "b8a103723b5f30ddaf8d0b211a3ddace", "18a64d7de48e1f7a54804114408f0433",
    "36bccf9492fd3a81dfaae522fd7f0ce9", "42fac0310bc93922b64be9e129306dc6",
    "f9bf92fe541402ae6666cfc0ee5fabe8", "9616a3647f41cf7714d25c06be606f3f",
    "237753d5c22b33272d26a602a617837f", "4f4658cef229f529b11907a5c0f86561",
    "4ad7c97353e47e5cb4edea0ae21cd919", "986809a29c1e3097e97134f109c926c8",
    "1998f05fb74c19b4a86ce11387fb34fa", "c77083aa3320196db463396465436c7f",
    "832881da7c60f09c27c704063f285ada", "132bf4e3313629b29c7a751d16101fe2",
    "4ad7c97353e47e5cb4edea0ae21cd919", "d2e8e62c7b540d9f49f4d1c96a2fc5d6",
    "42fac0310bc93922b64be9e129306dc6", "f9bf92fe541402ae6666cfc0ee5fabe8",
    "9616a3647f41cf7714d25c06be606f3f", "5e05380a70c9bebbe009a282b2a19657",
    "f4f5ee5502dd8fb2561567f052693328", "d2c22194d9fb9acacd87e4127b7ad0f7",
    "2a21a1486b6c9a36668f1425e90de7af", "e87d84083df0945a86374fdc5ec76224",
    "2430e3ba14543ccb13ee315beb88e903", "4f4658cef229f529b11907a5c0f86561",
    "4ad7c97353e47e5cb4edea0ae21cd919", "f4f5ee5502dd8fb2561567f052693328",
    "d2c22194d9fb9acacd87e4127b7ad0f7", "2a21a1486b6c9a36668f1425e90de7af",
    "e87d84083df0945a86374fdc5ec76224", "97d4ce5f709dcce0ff82c0961a4b21a7",
    "23e540eaed50958109ab6432d84fdec1", "9f4d15414a9abf8d267efc4171030b7c",
    "564e1237d943d1186dae088caf27643b", "d810bf1e82139012a42972ce8763de1b",
    "c0e906fe203feca4e4b3c29439d54ee3", "e3511cd9a041b5e198468e37d1920262",
    "cf400dbeedb9f6e6a55e39378a42c58c", "c9d75442e56447881203d1ff1e43fe39",
    "f4f5ee5502dd8fb2561567f052693328", "d2c22194d9fb9acacd87e4127b7ad0f7",
    "2a21a1486b6c9a36668f1425e90de7af", "e87d84083df0945a86374fdc5ec76224",
    "2430e3ba14543ccb13ee315beb88e903", "d2e8e62c7b540d9f49f4d1c96a2fc5d6",
    "529154a93960aff7432eb71d2618f1b4", "ce7603d2d7ae891f2592baa8e34f1333",
    "164a3e93bc714dbd7722bdc02b96104f", "fc982bb07dc967a7f2ca29a1125f02d0",
    "be4bed18af4852ae745c3dd6e1490243", "da29d0412b1022a733b587fe0eeee5c2",
    "9142dff705398393fd53807d7a0c49d5", "84026f562a6e58484c541bf5dec66186",
    "d407ce513d817ab0840bf2528758ee9b", "8e435185e4f65d0f342c8cee1d94a896"
    ]

    print("Decrypted values:")
    for i, encrypted in enumerate(encrypted_values):
        decrypted = decrypt_hex(encrypted, key, iv)
        print(f"0x{decrypted:x}")



if __name__ == "__main__":
    main()
```

The decrypted values are brought into conditional statements which we know is for a flag checker. You can easily make out some of the constratins but it's still pretty obfuscated(rust being rust). Sit down and understand how the constraints work, you'll realize the values involved in each are somehow interconnected with other constraints.

Some values in a constraint are straight of initialized to a single decrypted value which make it easier to get the other which involve this value.

So after getting all the constraints, you can write a z3 script as shown below to get the flag:

```py
from z3 import *

solver = Solver()

arr = [BitVec(f"arr_{i}", 32) for i in range(28)]

solver.add(arr[0] == (((0xfa99 & 0x2367) | 0xc80a) ^ 0xea65))
solver.add(arr[9] == arr[8], arr[8] == 0x31)
solver.add(arr[2] == arr[14], arr[14] == 0x74)
solver.add((arr[18] ^ 0x343180 ^ 0x9739378 ^ 0xd72f76b5 ^ 0xcc5dc719) == 0x12351326)
solver.add(arr[24] == (((arr[1] - 0xc1653aa0) & 0xda1cff3f) | 0x995980) ^ 0x1a99dde0)
solver.add(arr[13] == arr[26] + 0x2)
solver.add(arr[23] == ((((arr[0] - 0x1b37a000) & 0x959781db) | 0x4a6b0680) ^ 0xceeb06b2))
solver.add((((arr[3] ^ 0x62) | 0x8006c) & 0x69) == arr[20])
solver.add(arr[5] == (((arr[24] & 0x7634) >> 0x1f) ^ 0x63))
solver.add(arr[16] == 0x66)
solver.add(arr[1] == ((((~arr[12]) & arr[6]) ^ 0x9) | 0x68))
solver.add(arr[27] == (((((arr[17] + arr[22]) & 0x8435) ^ 0x50) | 0x7c)))
solver.add(arr[22] == arr[26] - 0x3)
solver.add(arr[6] == (((arr[16] ^ arr[18]) & 0xb00b) ^ 0x68))
solver.add(arr[26] == (arr[17] | 0x33))
solver.add(arr[3] == ((((arr[20] & 0x7634) >> 0x1f) ^ 0x63)) + 0x2)
solver.add((arr[19] ^ 0x343180 ^ 0x9739378 ^ 0xd72f76b5 ^ 0xcc5dc719) == 0x12351326)
solver.add(arr[7] == ((((~arr[12]) & arr[6]) ^ 0x9) | 0x68))
solver.add((arr[12] ^ 0x343180 ^ 0x9739378 ^ 0xd72f76b5 ^ 0xcc5dc719) == 0x12351321)
solver.add((arr[25] ^ 0xba6 + 0x4c00) == (arr[16] & 0x4696 ^ 0x57c4))
solver.add(arr[21] == ((((arr[12] - 0x1b37a000) & 0x959781db) | 0x4a6b0680) ^ 0xceeb06b2))
solver.add((arr[11] ^ 0x343180 ^ 0x9739378 ^ 0xd72f76b5 ^ 0xcc5dc719) == 0x12351326)
solver.add(arr[17] == arr[26], arr[26] == 0x33)
solver.add((((arr[14] ^ arr[23]) & 0x8e56) ^ 0xa144) == (arr[20] ^ 0xd289 - 0x3160))
solver.add(arr[15] == 0x5f)
solver.add(arr[10] == ((((arr[15] + 0x7a4756b0) | 0x42b1202) & 0x4cbc4a2e) ^ 0x4c2c4251))
solver.add(arr[4] == 0x7b)

for i in range(28):
    solver.add(And(arr[i] >= 0x20, arr[i] <= 0x7e))

if solver.check() == sat:
    model = solver.model()
    flag = ''.join(chr(model[arr[i]].as_long()) for i in range(28))
    print(f"Flag: {flag}")
else:
    print("No solution found")
```

A smarter approach would be to just debug and see how things are working, you can straight off get all the decrypted values without going through the hassle of making a decryption script. I was wondering if this could be angred. Who knows

The flag - `nite{chi11_ru5t_f3rric0xid3}`
