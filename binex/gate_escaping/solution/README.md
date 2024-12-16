## Gate Escaping Solution

This challenge is a sequel to Gate Keeping as it uses the same vm, but there are some slight modifications as this is a binex challenge.

1. Our code is way smaller and the player can see some strings that are being used.
2. The code size and instruction pointer have also become 8 bit. It also shows that the instruction pointer is acting as a signed bit.

The program is menu driven which asks for input and has option to exit. If a player observes internally, there is no cmp jump, it just jumps based on the choice given with a calculation of `ax + b` where a is 25 and b is 40. And now that you put the information that the instruction pointer is signed bit, it means that we can put something like `-5` and that would go behind the code block, and behind the code block is memory which the program is taking input for.

The challenge description mentions to read a flag file outside, so this means the user has to craft their own shellcode to open a file descriptor, read from it in memory and then write from memory to stdout using the opcode given. So from the last challenge it will help if the user did understand how the opcodes work.

Attached is my solve script of opening, reading, writing to stdout `flag` file and the source for the vm, again same as gate keeping but with the modified bytecode.

Hope you enjoyed the challenge
