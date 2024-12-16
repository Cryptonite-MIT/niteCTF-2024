import sys
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

blockSize = 16
key = b"YELLOW SUBMARINEYELLOW SUBMARINE" # 32-byte key
sectorNum = 1

def mul2(tweak):
    t = bytearray(tweak)
    carryIn = 0
    for i in range(len(t)):
        carryOut = t[i] >> 7
        t[i] = ((t[i] << 1) & 0xFF) | carryIn
        carryIn = carryOut
    if carryIn != 0:
        t[0] ^= 0x87
    return bytes(t)  # Ensure return is bytes

def xor_bytes(a, b):
    # Ensure both arguments are bytes
    return strxor(bytes(a), bytes(b))


def xts_decrypt(ciphertext):
    # Split key into k1, k2
    k1 = key[:16]
    k2 = key[16:]

    # Prepare AES blocks
    aes_k1 = AES.new(k1, AES.MODE_ECB)
    aes_k2 = AES.new(k2, AES.MODE_ECB)

    # Derive initial tweak
    tweak = bytearray(16)
    # sectorNum is placed into the first 8 bytes (little-endian)
    tweak[0:8] = sectorNum.to_bytes(8, 'little')
    # Encrypt tweak with k2
    tweak = bytearray(aes_k2.encrypt(bytes(tweak)))

    fullBlocks = len(ciphertext) // blockSize
    remainder = len(ciphertext) % blockSize

    if fullBlocks == 0:
        raise ValueError("xts: ciphertext too short")

    plaintext = bytearray(len(ciphertext))

    # Decrypt all but the last two blocks
    i = 0
    while i < fullBlocks - 1:
        ctBlock = ciphertext[i*blockSize:(i+1)*blockSize]
        # XOR ct with tweak
        ct_x = xor_bytes(ctBlock, tweak)
        # Decrypt with k1
        pt_x = aes_k1.decrypt(ct_x)
        # XOR pt_x with tweak
        ptBlock = xor_bytes(pt_x, tweak)
        plaintext[i*blockSize:(i+1)*blockSize] = ptBlock
        # mul2(tweak)
        tweak = mul2(tweak)
        i += 1

    if remainder == 0:
        # No CTS needed for last block
        ctBlock = ciphertext[i*blockSize:(i+1)*blockSize]
        ct_x = xor_bytes(ctBlock, tweak)
        pt_x = aes_k1.decrypt(ct_x)
        ptBlock = xor_bytes(pt_x, tweak)
        plaintext[i*blockSize:(i+1)*blockSize] = ptBlock
        return bytes(plaintext)

    # CTS logic:
    # i now points to penultimate full block
    lastFullBlockStart = (fullBlocks - 1) * blockSize
    lastFullCt = ciphertext[lastFullBlockStart:lastFullBlockStart+blockSize]

    # Backup tweak
    tBackup = tweak[:]

    # Advance tweak for partial block
    tweak = mul2(tweak)

    # Decrypt E (the penultimate ciphertext which is actually the E block)
    E_x = xor_bytes(lastFullCt, tweak)
    E_pt = aes_k1.decrypt(E_x)
    E = xor_bytes(E_pt, tweak)

    R = remainder
    P_n = E[:R]
    tail_of_C_n_1_orig = E[R:]

    reducedPenultimate = ciphertext[lastFullBlockStart+blockSize:lastFullBlockStart+blockSize+R]

    # Reconstruct C_{n-1_orig}s
    C_n_1_orig = bytearray(blockSize)
    C_n_1_orig[0:R] = reducedPenultimate
    C_n_1_orig[R:] = tail_of_C_n_1_orig

    # Restore tweak
    tweak = tBackup

    # Decrypt C_{n-1_orig}
    C_x = xor_bytes(C_n_1_orig, tweak)
    C_pt = aes_k1.decrypt(C_x)
    P_n_1_block = xor_bytes(C_pt, tweak)

    # Place P_{n-1} and P_n
    plaintext[lastFullBlockStart:lastFullBlockStart+blockSize] = P_n_1_block
    plaintext[lastFullBlockStart+blockSize:lastFullBlockStart+blockSize+R] = P_n

    return bytes(plaintext)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <ciphertext_file> <output_file>")
        sys.exit(1)

    ciphertext_file = sys.argv[1]
    output_file = sys.argv[2]

    with open(ciphertext_file, "rb") as f:
        ciphertext = f.read()

    plaintext = xts_decrypt(ciphertext)

    with open(output_file, "wb") as f:
        f.write(plaintext)

    print("Decryption successful! Plaintext written to:", output_file)
