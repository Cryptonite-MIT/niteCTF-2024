from functions import *
from Crypto.Util.number import *
yap = "0xef6ff40f0x8b18b98a0x9d0bbac80x6fb7ef770x2d951fc50xff8a25160xbbfdc2040xf220f9b10x5719a00d0xb1282eb90xd2f998d00xf69dbed50xcf060ec40x5927208f0x7d61ee430xfde565e30xf5b8ff5e0x3768f0dd0x6ded6f680x58a5ec3c0xa5f018b80xcaba6cf50xd56d9fd00x8d1746870x572e5fa90x93c6c27d0xede60bca0xb554453b0x83211af80x35d53b580x1d31f12e0x89b9ad360x81ace1c00x36dadebd0x146f624e0x4c10e9260xa3a2e4d60x728e18c90xb301ce5a0x283fc7020x310bcd900x833c81f80x23420e2a0x6af59eaf0xb2cc8a750x97512aef0x8a5b383f0xf0c0a4b"
random_chunks = [yap.split('0x')[1:][i:i+6] for i in range(0, len(yap.split('0x')[1:]), 6)]

flag = ""
for chunk in random_chunks:
    I_227_, I_228 = invertStep(untemper(int(chunk[0], 16)), untemper(int(chunk[3], 16)))
    I_228_, I_229 = invertStep(untemper(int(chunk[1], 16)), untemper(int(chunk[4], 16)))
    I_229_, I_230 = invertStep(untemper(int(chunk[2], 16)), untemper(int(chunk[5], 16)))
    I_228 += I_228_
    I_229 += I_229_
    seed1 = recover_Kj_from_Ii(I_230, I_229, I_228, 230)
    seed2 = recover_Kj_from_Ii(I_230+0x80000000, I_229, I_228, 230)
    try:
        flag += long_to_bytes(seed1).decode()
    except Exception:
        flag += long_to_bytes(seed2).decode()

print(flag)
    
