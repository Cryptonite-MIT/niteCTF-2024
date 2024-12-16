# SOLUTION

Take the Greek characters, map them to the corresponding English equivalents as given in the encryption, and then flip the bit of the `ciphertext` at the position `length - ASCII value of the corresponding English character`.

After flipping the bit, perform RSA to obtain one character, and loop through the process to perform RSA on all the Greek characters.

For non-Greek characters, simply use the same reverse alphabet function.
