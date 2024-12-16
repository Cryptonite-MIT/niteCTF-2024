# import random solution

go through the random.py provided to realise that the `random.getrandbits(n)` function has been used and modified to return the `0, 1, 2, 227, 228, 229` indexes of the state. \
There's a relation between `ith` and `i+227th` values of a state clearly demonstrated and inspired from here : https://stackered.com/blog/python-random-prediction/#seed-recovery-from-few-outputs \
it is clearly demonstrated how you can use these values to extract any seed under 32 bits. \
So the flag broken into chunks of 32 bits is seeded and the values of the above mentioned states can be untempered and extracted. \
Then perform above mentioned attack to retrieve the seed. <br><br>
Alternatively brute 32 bit sections, might take eternity but kudos for the boring solve ig.
