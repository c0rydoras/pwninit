#!/usr/bin/env python3

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
from pwn import str_input as input

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

    # good luck pwning :)

    rem.interactive()


if __name__ == "__main__":
    main()
