#!/usr/bin/env python

###############################################################################
## Stack related x86 shellcodes for ShellGen                                 ##
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

"Stack related shellcodes."

from __future__ import absolute_import
from ..base import Dynamic
from ..util import bit_length

import struct

__all__ = ["SubSP", "AllocaProbe"]

#-----------------------------------------------------------------------------#

class SubSP (Dynamic):
    """
    Stack pointer adjustment.

    When exploiting a stack buffer overflow, the stack pointer may be pointing
    somewhere within our shellcode. To avoid overwriting ourselves when using
    the stack, we need to adjust the stack pointer first.

    This shellcode tries to use the shortest variant of the C{SUB ESP, imm}
    instruction. It also tries to avoid null characters when possible.

    In some rare cases, the C{EAX} register may be used for temporary storage.
    """

    def __init__(self, offset):
        self.offset = offset

    def compile(self, state):
        bytes = self.__sub_esp_const(self.offset, state)
        if "\x00" not in bytes:
            self.add_encoding("nullfree")
        else:
            self.remove_encoding("nullfree")
            if state.requires_nullfree():
                raise RuntimeError("Could not compile without nulls")
        return bytes

    # 83 ec 01                sub    esp,0x1
    # 83 ec ff                sub    esp,-0x1
    # 81 ec 78 56 34 12       sub    esp,0x12345678
    # 81 ec 88 a9 cb ed       sub    esp,-0x12345678

    # 83 c4 01                add    esp,0x1
    # 83 c4 ff                add    esp,-0x1
    # 81 c4 78 56 34 12       add    esp,0x12345678
    # 81 c4 88 a9 cb ed       add    esp,-0x12345678

    # Optimized "sub esp, const". Tries to be null free.
    # May clobber eax if needed.
    def __sub_esp_const(self, const, state):
        pack   = struct.pack
        unpack = struct.unpack

        nullfree = state.requires_nullfree()

        # 0 bytes
        if const == 0:
            bytes = ""

        # 3 bytes
        elif -128 <= const <= 127:
            # sub esp, byte const
            bytes = "\x83\xec" + pack("b", const)

        # 6 bytes
        else:
            # sub esp, dword const
            if const < 0:
                bytes = "\x81\xec" + pack("<l", const)
            else:
                bytes = "\x81\xec" + pack("<L", const)
            if "\x00" in bytes:
                try:
                    # add esp, dword -const
                    if const < 0:
                        bytes = "\x81\xc4" + pack("<L", -const)
                    else:
                        bytes = "\x81\xc4" + pack("<l", -const)
                except Exception:
                    pass

            # 12 bytes, destroy eax
            if nullfree and ("\x00" in bytes):
                if const > 0:
                    packed = pack("<L", const)
                else:
                    packed = pack("<l", const)
                mask  = []
                xored = []
                for c in packed:
                    p = unpack("B", c)[0]
                    if p ^ 0x77 != 0:
                        mask.append(pack("B", 0x77))
                        xored.append(pack("B", p ^ 0x77))
                    else:
                        mask.append(pack("B", 0xFF))
                        xored.append(pack("B", p ^ 0xFF))
                bytes  = "\xb8" + "".join(xored)    # mov eax, const ^ mask
                bytes += "\x35" + "".join(mask)     # xor eax, mask
                bytes += "\x29\xc4"                 # sub esp, eax
                if "\x00" in bytes:
                    raise RuntimeError("Internal error!")

        return bytes

#-----------------------------------------------------------------------------#

class AllocaProbe (Dynamic):
    """
    Allocation probe.

    On modern operating systems, the stack size grows automatically as a
    program uses it. In order to detect stack usage, a "guard page" is placed
    at the top of the stack, so when it's accessed the operating system steps
    in, allocates more memory for the stack and places a new guard page.

    However, if we move the stack pointer I{past} the guard page, the operating
    system can't step in to allocate more memory, and we get an segmentation
    fault. This may happen for example when using the L{SubSP} shellcode with
    a value larger than the size of a memory page while the shellcode happened
    to be located right at the top of the stack. (Compilers also generate code
    like this when allocating a really large stack buffer).

    What this shellcode does is progressively access the pages towards the top
    of the stack, one memory page at a time, until the desired stack size is
    reached.
    """

    qualities = ("preserve_regs", "stack_balanced")
    encoding  = "nullfree"

    def __init__(self, size = 0x8000):
        self.size = size

    def compile(self, state):

        # Calculate the number of iterations we'll need.
        size = int((abs(self.size) + 0xFFF) / 0x1000)

        # Build the shellcode.
        bytes  = ""
        bytes += "\x60"                         #           pushad
        bytes += self.__mov_ecx_const(size, state) #        mov ecx, size
        bytes += "\x89\xe0"                     #           mov eax, esp
        bytes += "\x6a\x01"                     #           push 1
        bytes += "\x5a"                         #           pop edx
        bytes += "\xc1\xe2\x0c"                 #           shl edx, 12
        bytes += "\x29\xd0"                     # alloca:   sub eax, edx
        bytes += "\x85\x18"                     #           test [eax], ebx
        bytes += "\xe2\xfa"                     #           loop alloca
        bytes += "\x61"                         #           popad

        # Return the bytecode.
        return bytes

    # Optimized, null free "mov ecx, const".
    def __mov_ecx_const(self, const, state):
        pack   = struct.pack
        unpack = struct.unpack

        nullfree = state.requires_nullfree()

        #00000000  31C9              xor ecx,ecx
        #00000002  6A01              push byte +0x1
        #00000004  59                pop ecx
        #00000005  B911111111        mov ecx,0x11111111
        #0000000A  D1E1              shl ecx,1
        #0000000C  C1E110            shl ecx,byte 0x10
        #0000000F  81E911111111      sub ecx,0x11111111
        #00000015  F7D9              neg ecx
        #00000017  66B91111          mov cx,0x1111
        #0000001B  0FBFC9            movsx ecx,cx
        #0000001E  81F111111111      xor ecx,0x11111111

        # 2 bytes
        if const == 0:
            bytes  = "\x31\xc9"                     # xor ecx, ecx

        # 3 bytes
        elif -128 <= const < 127:
            bytes  = "\x6a" + chr(const)            # push const
            bytes += "\x51"                         # pop ecx

        else:

            # 5 bytes
            if const > 0:
                bytes = "\xb9" + pack("<L", const)      # mov ecx, const
            else:
                bytes = "\xb9" + pack("<l", const)      # mov ecx, const

            if nullfree and ("\x00" in bytes):

                # 6 bytes
                if const > 0 and ((const & (const - 1)) == 0):
                    shift = bit_length(const)
                    bytes  = "\x6a\x01"                 # push 1
                    bytes += "\x51"                     # pop ecx
                    bytes += "\xc1\xe1" + chr(shift)    # shl ecx, shift

                else:

                    # 7 bytes
                    try:
                        bytes  = "\x31\xc9"                  # xor ecx, ecx
                        bytes += "\xb9" + pack("<l", -const) # sub ecx, -const
                    except Exception:
                        bytes = ""

                    if not bytes or ("\x00" in bytes):

                        # 8 bytes
                        if const < 0 and (((-const) & ((-const) - 1)) == 0):
                            shift = bit_length(-const)
                            bytes  = "\x6a\x01"                 # push 1
                            bytes += "\x51"                     # pop ecx
                            bytes += "\xc1\xe1" + chr(shift)    # shl ecx, shift
                            bytes += "\xf7\xd9"                 # neg ecx

                        # 9 bytes
                        elif -32768 <= const < 32767:
                            bytes  = "\x66\xb9" + pack("<h", const)  # mov cx, const
                            bytes += "\x0f\xbf\xc9"                  # movsx ecx, cx

                    if not bytes or ("\x00" in bytes):

                        # 11 bytes
                        if const > 0:
                            packed = pack("<L", const)
                        else:
                            packed = pack("<l", const)
                        mask  = []
                        xored = []
                        for c in packed:
                            p = unpack("B", c)[0]
                            if p ^ 0x77 != 0:
                                mask.append(pack("B", 0x77))
                                xored.append(pack("B", p ^ 0x77))
                            else:
                                mask.append(pack("B", 0xFF))
                                xored.append(pack("B", p ^ 0xFF))
                        bytes  = "\xb9" + "".join(xored)    # mov ecx, const ^ mask
                        bytes += "\x81\xf1" + "".join(mask) # xor ecx, mask
                        if "\x00" in bytes:
                            raise RuntimeError("Internal error!")

        return bytes

#-----------------------------------------------------------------------------#

def test():
    "Unit test."

    #import traceback

    from shellgen import CompilerState

    def test_ok(clazz, size, nullfree = True):
        #try:
            shellcode = clazz(size)
            if nullfree:
                state = CompilerState()
                state.shared["encoding"] = "nullfree"
                shellcode.compile(state)
            is_nullfree = "\x00" not in shellcode.bytes
            claims_nullfree = "nullfree" in shellcode.encoding
            assert is_nullfree == claims_nullfree
        #    if is_nullfree != claims_nullfree:
        #        msg = "%s null check failed, size %.8X"
        #        print msg % (clazz.__name__, size)
        #        open("%s_%.8X.bin" % (clazz.__name__, size), "wb").write(bytes)
        #except Exception:
        #    msg = "%s failed with exception, size %.8X"
        #    print msg % (clazz.__name__, size)
        #    print traceback.format_exc()
        #    open("%s_%.8X.bin" % (clazz.__name__, size), "wb").write(bytes)

    def test_fail(clazz, size, nullfree = True):
        try:
            shellcode = clazz(size)
            if nullfree:
                state = CompilerState()
                state.shared["encoding"] = "nullfree"
                shellcode.compile(state)
            bytes = shellcode.bytes
            assert False
            #msg = "%s failed to raise exception, size %.8X"
            #print msg % (clazz.__name__, size)
            #open("%s_%.8X.bin" % (clazz.__name__, size), "wb").write(bytes)
        except Exception:
            pass

    test_fail(SubSP, 0x100000000)
    test_fail(SubSP, -0x80000001)

    test_ok(SubSP, 0xFFFFFFFF)
    test_ok(SubSP, 2147483648)
    test_ok(SubSP, -2147483648)
    test_ok(SubSP, -2147483647)
    test_ok(SubSP, 2147483647)
    test_ok(SubSP, 2147483646)
    test_ok(SubSP, 0x10000)
    test_ok(SubSP, -0x10000)
    test_ok(SubSP, 0xFFFF)
    test_ok(SubSP, -0xFFFF)
    test_ok(SubSP, 0xFF)
    test_ok(SubSP, -0xFF)
    test_ok(SubSP, 0x7F)
    test_ok(SubSP, -0x7F)
    test_ok(SubSP, 0)

    test_fail(AllocaProbe, 4294967296L * 4096)
    test_fail(AllocaProbe, -4294967296L * 4096)

    test_ok(AllocaProbe, -4294967295L * 4096)
    test_ok(AllocaProbe, -2147483649 * 4096)
    test_ok(AllocaProbe, 4294967295L * 4096)
    test_ok(AllocaProbe, -2147483648 * 4096)
    test_ok(AllocaProbe, -2147483647 * 4096)
    test_ok(AllocaProbe, 2147483647 * 4096)
    test_ok(AllocaProbe, 2147483646 * 4096)
    test_ok(AllocaProbe, 0x10000 * 4096)
    test_ok(AllocaProbe, -0x10000 * 4096)
    test_ok(AllocaProbe, 0xFFFF * 4096)
    test_ok(AllocaProbe, -0xFFFF * 4096)
    test_ok(AllocaProbe, 0xFF * 4096)
    test_ok(AllocaProbe, -0xFF * 4096)
    test_ok(AllocaProbe, 0x7F * 4096)
    test_ok(AllocaProbe, -0x7F * 4096)
    test_ok(AllocaProbe, 4294967296L)
    test_ok(AllocaProbe, -2147483649)
    test_ok(AllocaProbe, 4294967295L)
    test_ok(AllocaProbe, -2147483648)
    test_ok(AllocaProbe, -2147483647)
    test_ok(AllocaProbe, 2147483647)
    test_ok(AllocaProbe, 2147483646)
    test_ok(AllocaProbe, 0x10000)
    test_ok(AllocaProbe, -0x10000)
    test_ok(AllocaProbe, 0xFFFF)
    test_ok(AllocaProbe, -0xFFFF)
    test_ok(AllocaProbe, 0xFF)
    test_ok(AllocaProbe, -0xFF)
    test_ok(AllocaProbe, 0x7F)
    test_ok(AllocaProbe, -0x7F)
    test_ok(AllocaProbe, 0)
