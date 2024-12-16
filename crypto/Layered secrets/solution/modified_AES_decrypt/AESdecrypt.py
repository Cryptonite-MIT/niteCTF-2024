from AESdecryptfunc import * 
import math 
import io

if len(sys.argv) is not 3:
    sys.exit("Error, script needs two command-line arguments. (Ciphertext.txt File and plainhex.txt File)")
PassPhrase=""

while(len(PassPhrase)!=16):
    print("Enter in the 16 character passphrase to decrypt your text file %s" %sys.argv[1])
    PassPhrase=input()
    if(len(PassPhrase)<16):
        while(len(PassPhrase)!=16):
            PassPhrase=PassPhrase+"\00"
    if(len(PassPhrase)>16):
        print("Your passphrase was larger than 16, truncating passphrase.")
        PassPhrase=PassPhrase[0:16]

file=open(sys.argv[1], "r")
message=(file.read())
print("Inside your ciphertext message is:\n%s\n" % message)
file.close()

start=0
end=32
length=len(message)
loopmsg=0.00
loopmsg=math.ceil(length/32)+1
outputhex=""
asciioutput=""

PassPhrase=BitVector(textstring=PassPhrase)
roundkey1=findroundkey(PassPhrase.get_bitvector_in_hex(),1)
roundkey2=findroundkey(roundkey1,2)
roundkey3=findroundkey(roundkey2,3)
roundkey4=findroundkey(roundkey3,4)
roundkey5=findroundkey(roundkey4,5)
roundkey6=findroundkey(roundkey5,6)
roundkey7=findroundkey(roundkey6,7)
roundkey8=findroundkey(roundkey7,8)
roundkey9=findroundkey(roundkey8,9)
roundkey10=findroundkey(roundkey9,10)
roundkeys=[roundkey1,roundkey2,roundkey3,roundkey4,roundkey5,roundkey6,roundkey7,roundkey8,roundkey9,roundkey10]

FILEOUT = io.open(sys.argv[2], 'w', encoding='utf-8')

for y in range(1, loopmsg): 
    plaintextseg = message[start:end]

    bv1 = BitVector(hexstring=plaintextseg)
    bv2 = BitVector(hexstring=roundkeys[9])
    resultbv = bv1 ^ bv2
    myhexstring = resultbv.get_bitvector_in_hex()
    bv3 = BitVector(hexstring=myhexstring)
    myhexstring=invmixcolumn(bv3)
    myhexstring = invshiftrow(myhexstring)
    myhexstring = invsubbyte(myhexstring)

    bv1 = BitVector(hexstring=myhexstring)
    bv2 = BitVector(hexstring=roundkeys[8])
    resultbv = bv1 ^ bv2
    myhexstring = resultbv.get_bitvector_in_hex()
    myhexstring=invshiftrow(myhexstring)
    myhexstring=invsubbyte(myhexstring)

    for x in range(7, 4, -1):
        bv1 = BitVector(hexstring=myhexstring)
        bv2 = BitVector(hexstring=roundkeys[x])
        resultbv = bv1 ^ bv2
        myhexstring = resultbv.get_bitvector_in_hex()
        bv3 = BitVector(hexstring=myhexstring)
        myhexstring=invmixcolumn(bv3)
        myhexstring = invshiftrow(myhexstring)
        myhexstring = invsubbyte(myhexstring)
    
    bv1 = BitVector(hexstring=myhexstring)
    bv2 = BitVector(hexstring=roundkeys[4])
    resultbv = bv1 ^ bv2
    myhexstring = resultbv.get_bitvector_in_hex()
    bv3 = BitVector(hexstring=myhexstring)
    myhexstring=invmixcolumn(bv3)
    myhexstring = invsubbyte(myhexstring)

    for x in range(3, -1, -1):
        bv1 = BitVector(hexstring=myhexstring)
        bv2 = BitVector(hexstring=roundkeys[x])
        resultbv = bv1 ^ bv2
        myhexstring = resultbv.get_bitvector_in_hex()
        bv3 = BitVector(hexstring=myhexstring)
        myhexstring=invmixcolumn(bv3)
        myhexstring = invshiftrow(myhexstring)
        myhexstring = invsubbyte(myhexstring)

    bv1 = BitVector(hexstring=myhexstring)
    bv2 = PassPhrase
    resultbv = bv1 ^ bv2
    myhexstring = resultbv.get_bitvector_in_hex()

    start = start + 32 
    end = end + 32 

    replacementptr = 0
    while (replacementptr < len(myhexstring)):
        if (myhexstring[replacementptr:replacementptr + 2] == '0d'):
            myhexstring = myhexstring[0:replacementptr] + myhexstring[replacementptr+2:len(myhexstring)]
        else:
            replacementptr = replacementptr + 2

    outputhex = BitVector(hexstring=myhexstring)
    asciioutput = outputhex.get_bitvector_in_ascii()
    asciioutput=asciioutput.replace('\x00','')
    FILEOUT.write(asciioutput)

FILEOUT.close()

file2=io.open(sys.argv[2], "r", encoding='utf-8')
print("The decrypted message for the entire ciphertext is:\n%s\n" % file2.read())
file2.close()
