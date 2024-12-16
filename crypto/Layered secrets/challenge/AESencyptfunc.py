from BitVector import * 
import math 

def subbyte(myhexstring):
    loop2 = 0
    temp = ""
    temp2 = ""
    
    xor_constant = 0xAA  

    for loop in range(0, math.ceil(len(myhexstring)/2)):
        x = myhexstring[loop2]
        y = myhexstring[loop2 + 1]

        x = int(x, 16)
        y = int(y, 16)

        input_byte = (x << 4) | y  
        
        output_byte = input_byte ^ xor_constant
        
        output_hex = format(output_byte, '02x')
        
        temp2 = temp2 + output_hex
        
        loop2 = loop2 + 2
    
    return temp2

def mixcolumn(bv3):
    eightlim = BitVector(bitstring='100011011')
    two = BitVector(bitstring='0010')
    three = BitVector(bitstring='0011')

    newbv = BitVector(size=0)

    for i in range(0, 128, 32):
        bv = [bv3[i:i + 8], bv3[i + 8:i + 16], bv3[i + 16:i + 24], bv3[i + 24:i + 32]]

        tempbv = [
            bv[0].gf_multiply_modular(two, eightlim, 8) ^ bv[1].gf_multiply_modular(three, eightlim, 8) ^ bv[2] ^ bv[3],
            bv[1].gf_multiply_modular(two, eightlim, 8) ^ bv[2].gf_multiply_modular(three, eightlim, 8) ^ bv[0] ^ bv[3],
            bv[2].gf_multiply_modular(two, eightlim, 8) ^ bv[3].gf_multiply_modular(three, eightlim, 8) ^ bv[0] ^ bv[1],
            bv[3].gf_multiply_modular(two, eightlim, 8) ^ bv[0].gf_multiply_modular(three, eightlim, 8) ^ bv[1] ^ bv[2]
        ]

        for tbv in tempbv:
            newbv += tbv

    return newbv.get_bitvector_in_hex()

def shiftrow(temp2):

    if(len(temp2)==8):
        temp3=temp2[2]+temp2[3]+temp2[4]+temp2[5]+temp2[6]+temp2[7]+temp2[0]+temp2[1]
        return temp3
    else:
        temp3=temp2[0]+temp2[1]+temp2[10]+temp2[11]+temp2[20]+temp2[21]+temp2[30]+temp2[31]+temp2[8]+temp2[9]+temp2[18]+temp2[19]+temp2[28] + temp2[29] + temp2[6] + temp2[7] + temp2[16] + temp2[17] + temp2[26] + temp2[27] + temp2[4] + temp2[5] + temp2[14] + temp2[15] + temp2[24] + temp2[25] + temp2[2] + temp2[3] + temp2[12] + temp2[13] + temp2[22] + temp2[23]
        return temp3

def xor(temp1,temp2):
        temp1=BitVector(hexstring=temp1)
        temp2=BitVector(hexstring=temp2)
        temp3=temp1^temp2
        return temp3.get_bitvector_in_hex()

def findroundkey(temp1, case):
    rcon = [
        '01000000', '02000000', '04000000', '08000000', '10000000',
        '20000000', '40000000', '80000000', '1b000000', '36000000'
    ]

    w = [temp1[i:i + 8] for i in range(0, 32, 8)]
    temp2 = shiftrow(temp1[24:32])
    temp2 = subbyte(temp2)
    temp2 = xor(temp2, rcon[case - 1])

    for i in range(4):
        w.append(xor(w[i], temp2 if i == 0 else w[-1]))

    return ''.join(w[-4:])
