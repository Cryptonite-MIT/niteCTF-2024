## chaterine Solution

A tcache poison is possible to get a pointer in the stack
We can leak a stack address using a "%p" payload with a format string in the first input.

## Calculate the address of buffer

We need to calculate the offset of the required buffer from the leaked address. For this step you need to run a debugger on the binary in the docker. You can then see that the offset is `0x2130`.
Let the buffer address be `stack_addr`.

## Creating 2 chunks

Use the new message option to create 2 chunks using malloc.

## Free the chunks to push them into the tcache

Use the delete message option to free the chunks.

## Leaking heap address

Use the format string exploit in the Write message function to leak the heap address of the latest freed chunk.
One of the usable payloads can be `"%p %p %p"`.
This will leak the address of the chunk you are writing onto in the third spot.

## Poison the chunk in tcache

Now we have a heap address and the address of the buffer.
We can poison the tcache using the write message option and the payload
`p64(stack_addr ^ (heap_leak>>12))`.

## Create 2 new chunks

We create 2 new chunks again with the new message option.The first chunk will be allocated in the heap but the second allocation will have a pointer to the buffer address.

## Write spiderdrive onto the buffer

Use the write option onto the buffer to write spiderdrive.

## Clear the strcmp check

With the buffer now being written we can then try getting the admin acces which will be easily given to us and now we have shell acces.<br>
`cat flag.txt`
