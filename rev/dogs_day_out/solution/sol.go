func (c *Cipher) xtsDecrypt(plaintext, ciphertext []byte, sectorNum uint64) {
    if len(plaintext) < len(ciphertext) {
        panic("xts: plaintext buffer too small")
    }
    t := tweakPool.Get().(*[blockSize]byte)
    defer tweakPool.Put(t)
    // Derive tweak from sectorNum
    for i := range t {
        t[i] = 0
    }
    binary.LittleEndian.PutUint64(t[0:8], sectorNum)
    c.k2.Encrypt(t[:], t[:])
    fullBlocks := len(ciphertext) / blockSize
    remainder := len(ciphertext) % blockSize
    if fullBlocks == 0 {
        panic("xts: ciphertext too short")
    }

    var i int
    for i = 0; i < fullBlocks-1; i++ {
        ctBlock := ciphertext[i*blockSize : (i+1)*blockSize]
        ptBlock := plaintext[i*blockSize : (i+1)*blockSize]
        xor(ctBlock, t[:])
        c.k1.Decrypt(ptBlock, ctBlock)
        xor(ptBlock, t[:])
        mul2(t)
    }

    if remainder == 0 {
        // No CTS needed
        ctBlock := ciphertext[i*blockSize : (i+1)*blockSize]
        ptBlock := plaintext[i*blockSize : (i+1)*blockSize]
        xor(ctBlock, t[:])
        c.k1.Decrypt(ptBlock, ctBlock)
        xor(ptBlock, t[:])
        //log.Println(string(ptBlock))
        return
    }

    var tBackup [blockSize]byte
    copy(tBackup[:], t[:])

    //log.Println("Full CipherText: ", ciphertext[:])
    lastFullBlockStart := (fullBlocks - 1) * blockSize
    lastFullCt := ciphertext[lastFullBlockStart : lastFullBlockStart+blockSize]

    
    //log.Println("The penultimate ciphertext going for decryption:", lastFullCt)
    mul2(t)
    xor(lastFullCt, t[:])
    c.k1.Decrypt(lastFullCt, lastFullCt)
    xor(lastFullCt, t[:])
    //log.Println("The output of penultimate decryption ptCT:", lastFullCt)

    R := remainder
    P_n := lastFullCt[:R]
    tail_of_C_n_1_orig := lastFullCt[R:]

    reducedPenultimate := ciphertext[lastFullBlockStart+blockSize : lastFullBlockStart+blockSize+R]

    //log.Println("This is the incomplete portion going into the last block -> wrong rn", reducedPenultimate)
    //log.Println("This is the cipher stolen portion going into the last block", tail_of_C_n_1_orig)
    
    // CHANGE: Reconstruct C_{n-1_orig}
    C_n_1_orig := make([]byte, blockSize)
    copy(C_n_1_orig, reducedPenultimate)
    copy(C_n_1_orig[R:], tail_of_C_n_1_orig) 

    //log.Println("Reconstructed penultimate ciphertext:", C_n_1_orig)

    copy(t[:], tBackup[:])

    xor(C_n_1_orig, t[:])
    c.k1.Decrypt(C_n_1_orig, C_n_1_orig)
    xor(C_n_1_orig, t[:])

    copy(plaintext[lastFullBlockStart:lastFullBlockStart+blockSize], C_n_1_orig)
    copy(plaintext[lastFullBlockStart+blockSize:], P_n)

    //log.Println("This is the final decrypt: ", string(plaintext[:]))
}
