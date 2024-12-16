import sympy as sp
from Crypto.Util.number import *
file=open("flag.txt","r+")
flag=file.read()
language = {
    'A': 'Α', 'a': 'α',
    'B': 'Β', 'b': 'β',
    'C': 'Σ', 'c': 'σ',
    'D': 'Δ', 'd': 'δ',
    'E': 'Ε', 'e': 'ε',
    'F': 'Φ', 'f': 'φ',
    'G': 'Γ', 'g': 'γ',
    'H': 'Η', 'h': 'η',
    'I': 'Ι', 'i': 'ι',
    'J': 'Ξ', 'j': 'ξ',
    'K': 'Κ', 'k': 'κ',
    'L': 'Λ', 'l': 'λ',
    'M': 'Μ', 'm': 'μ',
    'N': 'Ν', 'n': 'ν',
    'O': 'Ο', 'o': 'ο',
    'P': 'Π', 'p': 'π',
    'Q': 'Θ', 'q': 'θ',
    'R': 'Ρ', 'r': 'ρ',
    'S': 'Σ', 's': 'ς',  
    'T': 'Τ', 't': 'τ',
    'U': 'Υ', 'u': 'υ',
    'V': 'Ω', 'v': 'ω',
    'W': 'Ψ', 'w': 'ψ',
    'X': 'Χ', 'x': 'χ',
    'Y': 'Υ', 'y': 'υ',
    'Z': 'Ζ', 'z': 'ζ'
}
def googly(number, position):
    mask = 1 << position
    return number ^ mask



def string_to_int(message):
    return int.from_bytes(message.encode('utf-8'), byteorder='big')

def int_to_string(number):
    return number.to_bytes((number.bit_length() + 7) // 8, byteorder='big').decode('utf-8')

def rsa_encrypt(message, public_key):
    n, e = public_key
    message_as_int = string_to_int(message)
    ciphertext = pow(message_as_int, e, n)
    return ciphertext

def reverse_alphabet(char):
    if char.isupper():  
        return chr(155 - ord(char))  
    elif char.islower():  
        return chr(219 - ord(char)) 
    elif(char=='_' or '{' or '}'):
        return 'e' 
ct=[] 
nlist=[]
file1=open("out.txt","w",encoding="utf=8")
for ch in flag:
    if(not sp.isprime(ord(ch))):
        transformed_char = reverse_alphabet(ch)
        file1.write(transformed_char)
    pre=ord(ch)%26
    if(pre<5):
        pre+=5
    p=getPrime(pre)
    q = getPrime(1024)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 65537 
    d = sp.mod_inverse(e, phi_n)
    pubkey = (n, e)
    privkey = (n, d)
    message = ch
    ciphertext = rsa_encrypt(message, pubkey)
    if(sp.isprime(ord(ch))):
        if(ch.isupper()):
            eng=chr(65+ciphertext%26)
            lan=language.get(eng)
            file1.write(lan)
            ciphertext=googly(ciphertext,ciph.bit_length()-ord(eng))
        else:
            eng=chr(97+ciphertext%26)
            lan=language.get(eng)
            file1.write(lan)
            ciphetext=googly(ciphertext,ciph.bit_length()-ord(eng))
    ct.append(ciphertext)
    nlist.append(n)

file1.write("\nct: \n")
for i in ct:
    file1.write(str(i)+", ")
file1.write("\nn: \n")
for j in nlist:
    file1.write(str(j)+", ")
