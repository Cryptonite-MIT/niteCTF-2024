from BitVector import * 
import math 

def findroundkey(temp1, case):
    w0, w1, w2, w3 = temp1[0:8], temp1[8:16], temp1[16:24], temp1[24:32]
    
    xor_constants = [
        '01000000', '02000000', '04000000', '08000000', '10000000', '20000000', 
        '40000000', '80000000', '1b000000', '36000000'
    ]
    
    temp2 = shiftrow(temp1[24:32])
    temp2 = subbyte(temp2)
    
    if 1 <= case <= 10:
        temp2 = xor(temp2, xor_constants[case - 1])
    
    w4 = xor(w0, temp2)
    w5 = xor(w1, w4)
    w6 = xor(w2, w5)
    w7 = xor(w3, w6)
    
    return w4 + w5 + w6 + w7

def xor(temp1,temp2):
        temp1=BitVector(hexstring=temp1)
        temp2=BitVector(hexstring=temp2)
        temp3=temp1^temp2
        return temp3.get_bitvector_in_hex()

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


def shiftrow(temp2):

    if(len(temp2)==8):
        temp3=temp2[2]+temp2[3]+temp2[4]+temp2[5]+temp2[6]+temp2[7]+temp2[0]+temp2[1]
        return temp3
    else:
        temp3=temp2[0]+temp2[1]+temp2[10]+temp2[11]+temp2[20]+temp2[21]+temp2[30]+temp2[31]+temp2[8]+temp2[9]+temp2[18]+temp2[19]+\
              temp2[28] + temp2[29] + temp2[6] + temp2[7] + temp2[16] + temp2[17] + temp2[26] + temp2[27] + temp2[4] + temp2[5] + \
              temp2[14] + temp2[15] + temp2[24] + temp2[25] + temp2[2] + temp2[3] + temp2[12] + temp2[13] + temp2[22] + temp2[23]
        return temp3

def invshiftrow(temp2):

    if (len(temp2) == 8):
        temp3 = temp2[6] + temp2[7] + temp2[0] + temp2[1] + temp2[2] + temp2[3] + temp2[4] + temp2[5]
        return temp3
    else:
        temp3=temp2[0]+temp2[1]+temp2[26]+temp2[27]+temp2[20]+temp2[21]+temp2[14]+temp2[15]+temp2[8]+temp2[9]\
              +temp2[2]+temp2[3]+temp2[28] + temp2[29] + temp2[22] + temp2[23] + temp2[16] + temp2[17] + temp2[10] + temp2[11]\
              + temp2[4] + temp2[5] + temp2[30] + temp2[31] + temp2[24] + temp2[25] + temp2[18] + temp2[19] + temp2[12] + temp2[13]\
              + temp2[6] + temp2[7]

        return temp3


def invsubbyte(myhexstring):
    loop2 = 0
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

def invmixcolumn(bv3):
    bv_chunks = [bv3[i:i+8] for i in range(0, 128, 8)]

    eightlim = BitVector(bitstring='100011011')
    constants = [
        ["1110", "1011", "1101", "1001"], 
        ["1001", "1110", "1011", "1101"],  
        ["1101", "1001", "1110", "1011"],  
        ["1011", "1101", "1001", "1110"]   
    ]

    def calculate_new_column(start_idx):
        column_result = BitVector(size=0)
        for row in range(4):
            temp = BitVector(size=8)
            for col in range(4):
                multiplier = BitVector(bitstring=constants[row][col])
                temp ^= bv_chunks[start_idx + col].gf_multiply_modular(multiplier, eightlim, 8)
            column_result += temp
        return column_result

    new_bv = BitVector(size=0)
    for i in range(0, len(bv_chunks), 4):
        new_bv += calculate_new_column(i)

    return new_bv.get_bitvector_in_hex()
