package main

import (
    "crypto/aes"
    "crypto/cipher"
    "encoding/binary"
    "errors"
    "fmt"
    "log"
    "os"
    "sync"
)

type Cipher struct {
    k1, k2 cipher.Block
}

// blockSize is the AES block size: 16 bytes.
const blockSize = 16

// tweakPool is used to reduce allocations.
var tweakPool = sync.Pool{
    New: func() interface{} {
        return new([blockSize]byte)
    },
}

// xor XORs src into dst in place.
func xor(dst, src []byte) {
    for i := range dst {
        dst[i] ^= src[i]
    }
}

// mul2 multiplies a 16-byte tweak by 2 in GF(2^128).
func mul2(tweak *[blockSize]byte) {
    var carryIn byte
    for j := range tweak {
        carryOut := tweak[j] >> 7
        tweak[j] = (tweak[j] << 1) | carryIn
        carryIn = carryOut
    }
    if carryIn != 0 {
        // XOR with 0x87 = 10000111 in binary (the AES polynomial)
        tweak[0] ^= 0x87
    }
}

// NewCipher creates an XTS cipher based on the provided key.
// key must be 32 bytes for AES-256, split into two 16-byte subkeys.
// The provided cipherFunc should be aes.NewCipher for AES-XTS.
func NewCipher(cipherFunc func([]byte) (cipher.Block, error), key []byte) (*Cipher, error) {
    if len(key)%2 != 0 || len(key) != 32 {
        return nil, errors.New("xts: key length must be 32 bytes (for AES-256-XTS)")
    }

    k1, err := cipherFunc(key[:len(key)/2])
    if err != nil {
        return nil, err
    }
    k2, err := cipherFunc(key[len(key)/2:])
    if err != nil {
        return nil, err
    }

    if k1.BlockSize() != blockSize {
        return nil, errors.New("xts: cipher block size must be 16")
    }

    return &Cipher{k1: k1, k2: k2}, nil
}

func (c *Cipher) Encrypt(ciphertext, plaintext []byte, sectorNum uint64) {
    if len(ciphertext) < len(plaintext) {
        panic("xts: ciphertext buffer too small")
    }

    t := tweakPool.Get().(*[blockSize]byte)
    defer tweakPool.Put(t)

    // Derive the tweak from sectorNum
    for i := range t {
        t[i] = 0
    }
    binary.LittleEndian.PutUint64(t[0:8], sectorNum)
    c.k2.Encrypt(t[:], t[:])

    fullBlocks := len(plaintext) / blockSize
    remainder := len(plaintext) % blockSize

    if fullBlocks == 0 {
        panic("xts: data too short for encryption")
    }

    var i int
    // Encrypt all but the last two blocks normally (if we have at least two blocks)
    for i = 0; i < fullBlocks-1; i++ {
        ptBlock := plaintext[i*blockSize : (i+1)*blockSize]
        ctBlock := ciphertext[i*blockSize : (i+1)*blockSize]

        xor(ptBlock, t[:])
        c.k1.Encrypt(ctBlock, ptBlock)
        xor(ctBlock, t[:])
        mul2(t)
    }

    if remainder == 0 {
        // No partial block, just encrypt the last full block normally
        ptBlock := plaintext[i*blockSize : (i+1)*blockSize]
        ctBlock := ciphertext[i*blockSize : (i+1)*blockSize]

        xor(ptBlock, t[:])
        c.k1.Encrypt(ctBlock, ptBlock)
        xor(ctBlock, t[:])
        return
    }

    // Handle the last two blocks with custom CTS where we pad with C_{n-1}

    // Penultimate block
    lastFullBlockStart := (fullBlocks - 1) * blockSize
    lastFullBlock := plaintext[lastFullBlockStart : lastFullBlockStart+blockSize]
    lastFullBlockEnc := ciphertext[lastFullBlockStart : lastFullBlockStart+blockSize]

    // Encrypt the penultimate block
    xor(lastFullBlock, t[:])
    c.k1.Encrypt(lastFullBlock, lastFullBlock)
    xor(lastFullBlock, t[:])
    copy(lastFullBlockEnc,lastFullBlock)
	//log.Println("Encryption Penultimate after encryption ****: ", lastFullBlock)
    // Advance tweak for the partial block
    mul2(t)

    R := remainder
    missing := blockSize - R

    // Prepare partial block by appending last (16 - R) bytes of penultimate ciphertext
    partialBlockStart := lastFullBlockStart + blockSize
    partialBuf := make([]byte, blockSize)
    copy(partialBuf, plaintext[partialBlockStart:partialBlockStart+R])
	//log.Println("Block going for encryption final partial:",partialBuf)

    copy(partialBuf[R:], lastFullBlockEnc[blockSize-missing:]) 
    // Now partialBuf is: P_n || tail of C_{n-1}
	//log.Println("Block going for encryption final partial with stealing:",partialBuf)
    // Encrypt this combined block
    xor(partialBuf, t[:])
    c.k1.Encrypt(partialBuf, partialBuf)
    xor(partialBuf, t[:])

    //log.Println("This is the output of final partial with stealing encryption: ", partialBuf)
    // partialBuf = E now
	// Place E as the penultimate ciphertext block
	copy(ciphertext[lastFullBlockStart:], partialBuf)


	// Now we must place the reduced penultimate block as the final block.
	// Since we took (16-R) bytes from C_{n-1_orig}, it's reduced to R bytes:
	reducedPenultimate := lastFullBlockEnc[:]

	// Place the reduced penultimate block as the last block
	finalBlockPos := lastFullBlockStart + blockSize
	copy(ciphertext[finalBlockPos:], reducedPenultimate)
    copy(ciphertext[lastFullBlockStart+blockSize:] , lastFullBlock)

}




func main() {
    // Hardcoded 32-byte key for AES-256-XTS
    key := []byte("YELLOW SUBMARINEYELLOW SUBMARINE") 

    // Validate key length
    if len(key) != 32 {
        log.Fatal("Key must be exactly 32 bytes")
    }

    // Initialize the XTS cipher
    cipherXTS, err := NewCipher(aes.NewCipher, key)
    if err != nil {
        log.Fatal(err)
    }

    inputFilePath := os.Args[1]

    // Read the plaintext from the input file
    plaintext, err := os.ReadFile(inputFilePath)
    if err != nil {
        log.Fatalf("Failed to read input file: %v\n", err)
    }

    // Prepare the ciphertext buffer
    ciphertext := make([]byte, len(plaintext))

    // Encrypt the plaintext
    cipherXTS.Encrypt(ciphertext, plaintext, 1)

    // Determine the output file path (append .enc to the original filename)
    outputFilePath := inputFilePath + ".enc"

    // Write the ciphertext to the output file
    err = os.WriteFile(outputFilePath, ciphertext, 0644)
    if err != nil {
        log.Fatalf("Failed to write encrypted file: %v\n", err)
    }

    fmt.Println("Encryption successful. Encrypted file:", outputFilePath)
}
