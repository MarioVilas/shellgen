#!/usr/bin/env python

###############################################################################
## GetPC x86 shellcodes for ShellGen                                         ##
###############################################################################

# Copyright (c) 2012-2015 Mario Vilas
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

"Get the execution pointer value."

from __future__ import absolute_import
from ..base import Dynamic, Decorator, CompileError
from ..util import is_stack_balanced

from struct import pack
from random import randint

__all__ = ["GetPC", "GetPC_Classic, ""GetPC_Alt", "GetPC_FPU", "GetPC_Wrapper"]

#-----------------------------------------------------------------------------#

class GetPC (Dynamic):
    "Randomly pick one of the GetPC variants defined in this module."

    provides  = "pc"
    encoding  = "nullfree"

    def __new__(cls, pcreg = "esi", delta = 0):
        choices = [GetPC_Classic, GetPC_Alt, GetPC_FPU]
        if delta:
            choices.remove(GetPC_Classic)   # 3 bytes too long!
        return choices[randint(0, len(choices) - 1)](pcreg, delta)

#-----------------------------------------------------------------------------#

class GetPC_Classic (Dynamic):
    "Classic GetPC implementation using a jump and a call."

    provides  = "pc"
    encoding  = "nullfree"

    def __init__(self, pcreg = "esi", delta = 0):
        self.pcreg = pcreg
        self.delta = delta

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
            raise CompileError("Invalid target register: %s" % pcreg)

        # Build the shellcode.
        bytes = jmp_f + pop[pcreg] + push[pcreg] + ret + call_b

        # No delta is normally needed, but if one is given, honor it.
        # This adds 3 bytes to the shellcode.
        if self.delta:
            add_b = {   # add reg, byte
                "eax" : "\x83\xC0",
                "ecx" : "\x83\xC1",
                "edx" : "\x83\xC2",
                "ebx" : "\x83\xC3",
                "ebp" : "\x83\xC4",
                "esp" : "\x83\xC5",
                "esi" : "\x83\xC6",
                "edi" : "\x83\xC7",
            }
            try:
                b_delta = pack("b", self.delta)
            except Exception:
                raise CompileError("Invalid delta: %r" % self.delta)
            bytes += add_b[pcreg] + b_delta

        # Update the compilation state.
        state.current["pc"] = pcreg

        # Return the bytecode.
        return bytes

#-----------------------------------------------------------------------------#

class GetPC_Alt (Dynamic):
    """
    Alternative GetPC implementation.
    Uses a call instruction that jumps on itself.

    The first public implementation of this technique is from Gerardo Richarte:
    U{http://archive.cert.uni-stuttgart.de/vuln-dev/2003/06/msg00098.html}

    This optimized version is based on the one published by Skylined:
    U{http://skypher.com/wiki/index.php/Hacking/Shellcode/GetPC}
    """

    provides  = "pc"
    encoding  = "nullfree"

    def __init__(self, pcreg = "esi", delta = 0):
        self.pcreg = pcreg
        self.delta = delta

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

        # Adjust the return address by adding delta + 5 to it.
        try:
            delta = self.delta + 5
            if delta:
                add_b = {
                    "eax" : "\x83\xC0",
                    "ecx" : "\x83\xC1",
                    "edx" : "\x83\xC2",
                    "ebx" : "\x83\xC3",
                    "ebp" : "\x83\xC4",
                    "esp" : "\x83\xC5",
                    "esi" : "\x83\xC6",
                    "edi" : "\x83\xC7",
                }
                b_delta = pack("b", delta)
        except Exception:
            raise CompileError("Invalid delta: %r" % self.delta)

        # Check the register name is valid.
        pcreg = self.pcreg.strip().lower()
        if pcreg not in pop:
            raise CompileError("Invalid target register: %s" % pcreg)

        # Build the shellcode.
        bytes = call_m1 + dec_alt[pcreg] + pop[pcreg]
        if delta:
            bytes += add_b[pcreg] + b_delta

        # Update the compilation state.
        state.current["pc"] = pcreg

        # Return the bytecode.
        return bytes

#-----------------------------------------------------------------------------#

class GetPC_FPU (Dynamic):
    """
    Another alternative GetPC implementation using the FPU state.

    The first public record of this idea is from "noir":
    U{http://archive.cert.uni-stuttgart.de/vuln-dev/2003/06/msg00116.html}

    This optimized version is based on the one published by Skylined:
    U{http://skypher.com/wiki/index.php/Hacking/Shellcode/GetPC}

    Disassembly::
        # $+0  D9EE       FLDZ                ; Floating point stores $+0 in its environment
        # $+2  D974E4 F4  FSTENV SS:[ESP-0xC] ; Save environment at ESP-0xC; now [ESP] = $+0
        # $+6  59         POP ECX             ; ECX = $+0
        # $+7  83E9 F2    SUB ECX, -10        ; ECX = $+10
        # $+10 ...

    @note:
        This shellcode may be hard to single-step on because it uses the stack
        space at negative ESP offsets, which is overwritten by some debuggers.
    """

    provides  = "pc"
    encoding  = "nullfree"

    def __init__(self, pcreg = "esi", delta = 0):
        self.pcreg = pcreg
        self.delta = delta

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
        try:
            delta = self.delta - 10
            if delta:
                add_b = {
                    "eax" : "\x83\xE8",
                    "ecx" : "\x83\xE9",
                    "edx" : "\x83\xEA",
                    "ebx" : "\x83\xEB",
                    "ebp" : "\x83\xEC",
                    "esp" : "\x83\xED",
                    "esi" : "\x83\xEE",
                    "edi" : "\x83\xEF",
                }
                b_delta = pack("b", delta)
        except Exception:
            raise CompileError("Invalid delta: %r" % self.delta)

        # Check the register name is valid.
        pcreg = self.pcreg.strip().lower()
        if pcreg not in pop:
            raise CompileError("Invalid target register: %s" % pcreg)

        bytes = "\xD9\xEE\xD9\x74\xE4\xF4" + pop[pcreg]
        if delta:
            bytes += add_b[pcreg] + b_delta

        # Update the compilation state.
        state.current["pc"] = pcreg

        # Return the bytecode.
        return bytes

#-----------------------------------------------------------------------------#

class GetPC_Wrapper (Decorator):
    """
    This GetPC variant wraps shellcodes by providing them the address of their
    payload. Adds 10 bytes to the shellcode.

    @warn: The child shellcode MUST be stack balanced.
    """
    provides  = "pc"
    encoding  = "nullfree"

    def __init__(self, child, pcreg = "esi"):
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
            raise CompileError("Invalid target register: %s" % pcreg)

        # Get the child bytecode.
        state.current["pc"] = pcreg
        bytes = self.child.compile(state)

        # Check the decoder stub doesn't exceed the maximum size.
        if len(bytes) > 128:
            raise CompileError("Child is larger than 128 bytes")

        # Check the child is stack balanced.
        if not is_stack_balanced(self.child):
            raise CompileError("Child must be stack balanced")

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
            raise CompileError("Cannot compile without nulls")

        # Return the bytecode.
        return bytes

#-----------------------------------------------------------------------------#

def test():
    "Unit test."

    # True to write out shellcode samples to disk.
    WRITE = False
    #WRITE = True

    # This is for manual testing.
    if WRITE:
        open("GetPC_Classic.bin","wb").write(GetPC_Classic().bytes)
        open("GetPC_Classic_2.bin","wb").write(GetPC_Classic("eax",100).bytes)
        open("GetPC_Alt.bin","wb").write(GetPC_Alt().bytes)
        open("GetPC_Alt_2.bin","wb").write(GetPC_Alt("eax",-5).bytes)
        open("GetPC_FPU.bin","wb").write(GetPC_FPU().bytes)
        open("GetPC_FPU_2.bin","wb").write(GetPC_FPU("eax",10).bytes)
        from shellgen.x86.debug import Breakpoint
        open("GetPC_Wrapper.bin","wb").write(GetPC_Wrapper(Breakpoint()).bytes)

    from shellgen import Raw, CompilerState

    def test_gpc(clazz, *argv, **argd):
        shellcode = clazz(*argv, **argd)
        assert shellcode.length == len(shellcode.bytes)
        assert "\x00" not in shellcode.bytes
    test_gpc(GetPC_Classic)
    test_gpc(GetPC_Alt)
    test_gpc(GetPC_FPU)
    test_gpc(GetPC)

    assert GetPC_Classic().length == GetPC_Alt().length == GetPC_FPU().length

    for pcreg in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"):
        for delta in xrange(-128, 128):
            test_gpc(GetPC_Classic, pcreg, delta)
        for delta in xrange(-133, 123):
            test_gpc(GetPC_Alt, pcreg, delta)
        for delta in xrange(-118, 138):
            test_gpc(GetPC_FPU, pcreg, delta)
        for delta in xrange(-118, 123):
            test_gpc(GetPC, pcreg, delta)

    def test_gpc_fail(clazz, *argv, **argd):
        try:
            clazz(*argv, **argd).bytes
            assert False
        except CompileError:
            pass

    for pcreg in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"):
        for delta in (-129, 128):
            test_gpc_fail(GetPC_Classic, pcreg, delta)
        for delta in (-134, 124):
            test_gpc_fail(GetPC_Alt, pcreg, delta)
        for delta in (-119, 139):
            test_gpc_fail(GetPC_FPU, pcreg, delta)
        for delta in (-134, 139):
            test_gpc_fail(GetPC, pcreg, delta)

    test_gpc_fail(GetPC_Wrapper, Raw("this is a test"))
    test_shellcode = Raw("this is a test", qualities="stack_balanced")
    test_wrapper = GetPC_Wrapper(test_shellcode)
    state = CompilerState()
    state.shared["encoding"] = "nullfree"
    test_wrapper.compile(state)
    assert test_wrapper.length == len(test_wrapper.bytes)
    assert "\x00" not in test_wrapper.bytes
    assert test_wrapper.length > test_shellcode.length
    expected_length = GetPC_Classic().length + test_shellcode.length
    assert test_wrapper.length == expected_length

    def test_compile_fail(shellcode, state = None):
        try:
            shellcode.compile(state)
            assert False
        except CompileError:
            pass

    test_shellcode = Raw("this has a null\0", qualities="stack_balanced")
    test_wrapper = GetPC_Wrapper(test_shellcode)
    state = CompilerState()
    state.shared["encoding"] = "nullfree"
    test_compile_fail(test_wrapper, state)
    test_wrapper.compile()
    assert "nullfree" not in test_wrapper.encoding

    test_shellcode1 = Raw("this is a test", qualities="stack_balanced")
    test_shellcode2 = Raw("this is a test", qualities="no_stack")
    test_shellcode = test_shellcode1 + test_shellcode2
    test_wrapper = GetPC_Wrapper(test_shellcode)
    expected_length = GetPC_Classic().length + (len("this is a test") * 2)
    assert test_wrapper.length == expected_length

    test_shellcode1 = Raw("this is a test", qualities="no_stack")
    test_shellcode2 = test_shellcode1 + Raw("this is a test")
    test_shellcode = test_shellcode2 + Raw("this is a test",
                                           qualities="stack_balanced")
    test_wrapper = GetPC_Wrapper(test_shellcode)
    test_compile_fail(test_wrapper)

    test_shellcode = Raw("A" * 0x1000, qualities="stack_balanced")
    test_wrapper = GetPC_Wrapper(test_shellcode)
    test_compile_fail(test_wrapper)
