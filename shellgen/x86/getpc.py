#!/usr/bin/env python

###############################################################################
## GetPC x86 shellcodes for ShellGen                                         ##
###############################################################################

# Copyright (c) 2012-2013 Mario Vilas
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

from __future__ import absolute_import
from ..base import Dynamic, Decorator
from ..util import is_stack_balanced

from struct import pack

__all__ = ["GetPC", "GetPC_Alt", "GetPC_FPU", "GetPC_Wrapper"]

#-----------------------------------------------------------------------------#

# Classic GetPC implementation using a jump and a call.
class GetPC (Dynamic):
    provides  = "pc"
    encoding  = "nullfree"
    length    = 10

    def __init__(self, pcreg = "ecx"):
        self.pcreg = pcreg

    def compile(self, state):

        # Jump forward to the call instruction.
        jmp_f = "\xEB\x03"

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
        pcreg = self.pcreg.strip().lower()
        if pcreg not in pop:
            raise ValueError("Invalid target register: %s" % pcreg)

        # Build the shellcode.
        bytes = jmp_f + pop[pcreg] + push[pcreg] + ret + call_b

        # Update the compilation state.
        state.current["pc"] = pcreg

        # Return the bytecode.
        return bytes

#-----------------------------------------------------------------------------#

# Alternative GetPC implementation using a call instruction jumping on itself.
# As far as I know the first to implement this was Gerardo Richarte:
#     http://archive.cert.uni-stuttgart.de/vuln-dev/2003/06/msg00098.html
# This optimized version is based on the one published by Skylined:
#     http://skypher.com/wiki/index.php/Hacking/Shellcode/GetPC
class GetPC_Alt (Dynamic):
    provides  = "pc"
    encoding  = "nullfree"
    length    = 10

    def __init__(self, pcreg = "ecx"):
        self.pcreg = pcreg

    def compile(self, state):

        # This "call $+4" instruction jumps on the last byte of itself, so the
        # next instruction uses an alternate encoding of the "dec" instruction
        # to decrement a harmless register.
        call_m1 = "\xE8\xFF\xFF\xFF\xFF"

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
        pcreg = self.pcreg.strip().lower()
        if pcreg not in pop:
            raise ValueError("Invalid target register: %s" % pcreg)

        # Build the shellcode.
        bytes = call_m1 + dec_alt[pcreg] + pop[pcreg] + add_5[pcreg]

        # Update the compilation state.
        state.current["pc"] = pcreg

        # Return the bytecode.
        return bytes

#-----------------------------------------------------------------------------#

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
    length    = 10

    def __init__(self, pcreg = "ecx"):
        self.pcreg = pcreg

    def compile(self, state):

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
        pcreg = self.pcreg.strip().lower()
        if pcreg not in pop:
            raise ValueError("Invalid target register: %s" % pcreg)

        bytes = "\xD9\xEE\xD9\x74\xE4\xF4" + pop[pcreg] + add_10[pcreg]

        # Update the compilation state.
        state.current["pc"] = pcreg

        # Return the bytecode.
        return bytes

#-----------------------------------------------------------------------------#

# This one wraps shellcodes by providing them the address of their payload.
# The child shellcode MUST be stack balanced.
# Adds 10 bytes to the shellcode.
class GetPC_Wrapper (Decorator):
    provides  = "pc"
    encoding  = "nullfree"

    def __init__(self, child, pcreg = "ecx"):
        super(GetPC_Wrapper, self).__init__(child)
        self.pcreg = pcreg

    def compile(self, state):

        # If there is no child, do nothing.
        if not self.child:
            return ""

        # Pop register instructions.
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

        # Push register instructions.
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

        # Check the register name is valid.
        pcreg = self.pcreg.strip().lower()
        if pcreg not in pop:
            raise ValueError("Invalid target register: %s" % pcreg)

        # Get the child bytecode.
        state.current["pc"] = pcreg
        bytes = self.child.compile(state)

        # Check the decoder stub doesn't exceed the maximum size.
        if len(bytes) > 128:
            raise RuntimeError("Child is larger than 128 bytes")

        # Check the child is stack balanced.
        if not is_stack_balanced(self.child):
            raise RuntimeError("Child must be stack balanced")

        # ASM: Jump to the call instruction.
        jmp_f = "\xEB" + pack("b", len(bytes) + 3)

        # ASM: Pop the return address from the stack.
        pop_pc = pop[pcreg]

        # ASM: Push it back again.
        push_pc = push[pcreg]

        # ASM: Return to the payload.
        ret = "\xC3"

        # ASM: Call to the pop instruction.
        call_b = "\xE8" + pack("<l", -8 - len(bytes))

        # Build the shellcode.
        self.child.relocate(len(jmp_f + pop_pc + push_pc))
        bytes = self.child.bytes
        bytes = jmp_f + pop_pc + push_pc + bytes + ret + call_b

        # Check the bytecode for nulls.
        if state.requires_nullfree() and "\x00" in bytes:
            raise RuntimeError("Cannot compile without nulls")

        # Return the bytecode.
        return bytes

#-----------------------------------------------------------------------------#

def test():
    "Unit test."

    # This is for manual testing.
##    open("GetPC.bin","wb").write(GetPC().bytes)
##    open("GetPC_Alt.bin","wb").write(GetPC_Alt().bytes)
##    open("GetPC_FPU.bin","wb").write(GetPC_FPU().bytes)
##    from shellgen.x86.debug import Breakpoint
##    open("GetPC_Wrapper.bin","wb").write(GetPC_Wrapper(Breakpoint()).bytes)

    from shellgen import Raw, CompilerState

    def test_gpc(clazz):
        shellcode = clazz()
        assert shellcode.length == len(shellcode.bytes)
        assert "\x00" not in shellcode.bytes
    test_gpc(GetPC)
    test_gpc(GetPC_Alt)
    test_gpc(GetPC_FPU)

    assert GetPC.length == GetPC_Alt.length == GetPC_FPU.length

    try:
        GetPC_Wrapper(Raw("this is a test")).bytes
        assert False
    except RuntimeError:
        pass
    test_shellcode = Raw("this is a test", qualities="stack_balanced")
    test_wrapper = GetPC_Wrapper(test_shellcode)
    state = CompilerState()
    state.shared["encoding"] = "nullfree"
    test_wrapper.compile(state)
    assert test_wrapper.length == len(test_wrapper.bytes)
    assert "\x00" not in test_wrapper.bytes
    assert test_wrapper.length > test_shellcode.length
    assert test_wrapper.length == GetPC.length + test_shellcode.length

    test_shellcode = Raw("this has a null\0", qualities="stack_balanced")
    test_wrapper = GetPC_Wrapper(test_shellcode)
    state = CompilerState()
    state.shared["encoding"] = "nullfree"
    try:
        test_wrapper.compile(state)
        assert False
    except RuntimeError:
        pass
    test_wrapper.compile()
    assert "nullfree" not in test_wrapper.encoding

    test_shellcode1 = Raw("this is a test", qualities="stack_balanced")
    test_shellcode2 = Raw("this is a test", qualities="no_stack")
    test_shellcode = test_shellcode1 + test_shellcode2
    test_wrapper = GetPC_Wrapper(test_shellcode)
    assert test_wrapper.length == GetPC.length + (len("this is a test") * 2)

    test_shellcode1 = Raw("this is a test", qualities="no_stack")
    test_shellcode2 = test_shellcode1 + Raw("this is a test")
    test_shellcode = test_shellcode2 + Raw("this is a test", qualities="stack_balanced")
    test_wrapper = GetPC_Wrapper(test_shellcode)
    try:
        test_wrapper.compile()
        assert False
    except RuntimeError:
        pass

    test_shellcode = Raw("A" * 0x1000, qualities="stack_balanced")
    test_wrapper = GetPC_Wrapper(test_shellcode)
    try:
        test_wrapper.compile()
        assert False
    except RuntimeError:
        pass
