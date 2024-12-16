# Mixed-signal Solution

There's a buffer overflow available, use that to set context by calling `rt_sigreturn` using the given `syscall` instruction.

Carefully analyze the seccomp and you'll notice we have `sendfile` available and flag's file descriptor hasn't been closed yet. Use `sendfile` to get the flag.

[Solve script](solve.py)
