#!/usr/bin/env python3

from functools import partial
from pwn import (
    ELF,
    args,
    context,
    cyclic,
    flat,
    gdb,
    hexdump,
    info,
    p64,
    pause,
    process,
    remote,
    u64,
)

{bindings}

context.binary = {bin_name}

GDBSCRIPT = """
dprintf malloc, "malloc(%zu)\\n", $rdi
dprintf free, "free(%p)\\n", $rdi
""".strip()


def conn():
    if args.REMOTE:
        rem = remote("localhost", 1337)
    else:
        rem = process({proc_args})
        if not args.NO_DEBUG:
            gdb.attach(rem, gdbscript=GDBSCRIPT)

    return rem


def main():
    rem = conn()
    sendlineafter = rem.sendlineafter
    sendline = rem.sendline
    send = rem.send

    opt = partial(rem.sendlineafter, b">")
    opt2 = partial(rem.sendlineafter, b":")

    rem.interactive()


if __name__ == "__main__":
    main()
