#!/usr/bin/env python

###############################################################################
## Stack related x86-64 shellcodes for ShellGen                              ##
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

# Stack pointer adjustment.
class SubSP (Dynamic):
    """
    Stack pointer adjustment.

    When exploiting a stack buffer overflow, the stack pointer may be pointing
    somewhere within our shellcode. To avoid overwriting ourselves when using
    the stack, we need to adjust the stack pointer first.

    This shellcode tries to use the shortest variant of the C{SUB RSP, imm}
    instruction. It also tries to avoid null characters when possible.

    Since it's not possible to have a 64-bit immediate value in an arithmetic
    operation, the shellcode may use C{RAX} and/or C{RDX} for storage. However,
    you won't need to make stack pointer adjustements larger than C{0xFFFFFFFF}
    too often, so you probably don't need to worry about it. ;)
    """

    encoding = "nullfree"

    def __init__(self, offset):
        self.offset = offset

    def compile(self, state):
        bytes = self.__sub_rsp_const(self.offset, state)
        if "\x00" not in bytes:
            self.add_encoding("nullfree")
        else:
            self.remove_encoding("nullfree")
        return bytes

    # 48 83 ec 01                       sub    rsp,  0x1
    # 48 83 ec ff                       sub    rsp, -0x1
    # 48 81 ec 78 56 34 12              sub    rsp,  0x12345678
    # 48 81 ec 88 a9 cb ed              sub    rsp, -0x12345678

    # 48 83 c4 01                       add    rsp,  0x1
    # 48 83 c4 ff                       add    rsp, -0x1
    # 48 81 c4 78 56 34 12              add    rsp,  0x12345678
    # 48 81 c4 88 a9 cb ed              add    rsp, -0x12345678

    # 48 b8 21 43 65 87 78 56 34 12     mov    rax, 0x1234567887654321
    # 48 29 c4                          sub    rsp, rax
    # 48 01 c4                          add    rsp, rax

    # 48 BA 44 44 33 33 22 22 11 11     mov    rdx, 0x1111222233334444
    # 48 31 D0                          xor    rax, rdx

    # Optimized "sub rsp, const". Tries to be null free.
    # May clobber the contents of rax if const is too big to fit in a dword.
    def __sub_rsp_const(self, const, state):
        pack   = struct.pack
        unpack = struct.unpack

        nullfree = state.requires_nullfree()

        # 0 bytes
        if const == 0:
            bytes = ""

        # 4 bytes
        elif -128 <= const <= 127:
            # sub rsp, byte const
            bytes = "\x48\x83\xec" + pack("b", const)

        else:
            bytes = ""

            # 7 bytes
            if -2147483648 <= const <= 2147483647:
                # sub rsp, dword const
                bytes = "\x48\x81\xec" + pack("<l", const)
                if "\x00" in bytes:
                    # add rsp, dword -const
                    try:
                        bytes = "\x48\x81\xc4" + pack("<l", -const)
                    except Exception:
                        pass

            # 13 bytes, destroy rax
            if not bytes or (nullfree and ("\x00" in bytes)):
                # mov rax, const
                # sub rsp, rax
                if const < 0:
                    bytes = "\x48\xb8" + pack("<q", const) + "\x48\x29\xc4"
                else:
                    bytes = "\x48\xb8" + pack("<Q", const) + "\x48\x29\xc4"
                if "\x00" in bytes:
                    try:
                        # mov rax, -const
                        # add rsp, rax
                        if const < 0:
                            bytes = "\x48\xb8" + pack("<Q", -const) + "\x48\x01\xc4"
                        else:
                            bytes = "\x48\xb8" + pack("<q", -const) + "\x48\x01\xc4"
                    except Exception:
                        pass

                    # 26 bytes, destroy rax & rdx
                    if nullfree and ("\x00" in bytes):
                        if const > 0:
                            packed = pack("<Q", const)
                        else:
                            packed = pack("<q", const)
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
                        bytes  = "\x48\xb8" + "".join(xored)    # mov rax, mask
                        bytes += "\x48\xba" + "".join(mask)     # mov rdx, const ^ mask
                        bytes += "\x48\x31\xd0"                 # xor rax, rdx
                        bytes += "\x48\x01\xc4"                 # add rsp, rax
                        if "\x00" in bytes:
                            raise RuntimeError("Internal error!")

        if nullfree and ("\x00" in bytes):
            raise RuntimeError("Could not compile without nulls")

        return bytes

#-----------------------------------------------------------------------------#

# Allocation probe.
class AllocaProbe (Dynamic):
    qualities = ("preserve_regs", "stack_balanced")
    encoding  = "nullfree"

    def __init__(self, size = 0x8000):
        self.size = size

    def compile(self, state):

        # Calculate the number of iterations we'll need.
        size = int((abs(self.size) + 0xFFF) / 0x1000)

        # Build the shellcode.
        bytes  = ""
        bytes += "\x50"                         #           push rax
        bytes += "\x51"                         #           push rcx
        bytes += "\x52"                         #           push rdx
        bytes += self.__mov_rcx_const(size, state) #        mov rcx, size
        bytes += "\x48\x89\xe0"                 #           mov rax, rsp
        bytes += "\x6a\x01"                     #           push 1
        bytes += "\x5a"                         #           pop rdx
        bytes += "\x48\xc1\xe2\x0c"             #           shl rdx, 12
        bytes += "\x48\x29\xd0"                 # alloca:   sub rax, rdx
        bytes += "\x48\x85\x18"                 #           test [rax], rbx
        bytes += "\xe2\xf8"                     #           loop alloca
        bytes += "\x5a"                         #           pop rdx
        bytes += "\x59"                         #           pop rcx
        bytes += "\x58"                         #           pop rax

        # Fail if we needed to make it null free but couldn't.
        if state.requires_nullfree() and "\x00" in bytes:
            raise RuntimeError("Could not compile without nulls")

        # Return the bytecode.
        return bytes

    # Optimized, null free "mov rcx, const".
    # May clobber rax if needed.
    def __mov_rcx_const(self, const, state):
        pack   = struct.pack
        unpack = struct.unpack

        nullfree = state.requires_nullfree()

        #00000000  4831C9                   xor rcx,rcx
        #00000003  6A01                     push byte +0x1
        #00000005  59                       pop rcx
        #00000006  48B82222222211111111     mov rax,0x1111111122222222
        #00000010  48B92222222211111111     mov rcx,0x1111111122222222
        #0000001A  48D1E1                   shl rcx,1
        #0000001D  48C1E110                 shl rcx,byte 0x10
        #00000021  48F7D9                   neg rcx
        #00000024  66B91111                 mov cx,0x1111
        #00000028  B911111111               mov ecx,0x11111111
        #0000002D  480FBFC9                 movsx rcx,cx
        #00000031  4863C9                   movsxd rcx,ecx
        #00000034  480FB7C9                 movzx rcx,cx
        #00000038  48FFC1                   inc rcx
        #0000003B  48FFC9                   dec rcx
        #0000003E  4831C1                   xor rcx,rax

        bytes = ""

        # 3 bytes
        if const == 0:
            bytes  = "\x48\x31\xc9"         # xor rcx, rcx

        # 3 bytes
        elif -128 <= const < 127:
            bytes  = "\x6a" + chr(const)            # push const
            bytes += "\x51"                         # pop rcx

        # 7 bytes
        elif const > 0 and ((const & (const - 1)) == 0):
            shift = bit_length(const) - 1
            bytes  = "\x6a\x01"                         # push 1
            bytes += "\x51"                             # pop rcx
            bytes += "\x48\xc1\xe1" + pack("B", shift)  # shl rcx, shift

        else:

            # 8 bytes
            if 0 < const < 4294967295L:
                bytes  = "\x48\x31\xc9"                 # xor rcx, rcx
                bytes += "\xb9" + pack("<L", const)     # mov ecx, const

            if not bytes or (nullfree and "\x00" in bytes):

                # 10 bytes
                if const < 0 and (((-const) & ((-const) - 1)) == 0):
                    shift = bit_length(-const) - 1
                    bytes  = "\x6a\x01"                        # push 1
                    bytes += "\x51"                            # pop rcx
                    bytes += "\x48\xc1\xe1" + pack("B", shift) # shl rcx, shift
                    bytes += "\x48\xf7\xd9"                    # neg rcx

                else:

                    # 10 bytes
                    if const > 0:
                        bytes = "\x48\xb9" + pack("<Q", const)  # mov rcx, const
                    else:
                        bytes = "\x48\xb9" + pack("<q", const)  # mov rcx, const

                    if nullfree and "\x00" in bytes:

                        # 10 bytes
                        if -32768 <= const < 32767:
                            bytes  = "\x66\xb9" + pack("<h", const) # mov cx, const
                            bytes += "\x48\x0f\xbf\xc9"             # movsx rcx, cx

                        # 10 bytes
                        elif 0 < const < 65535:
                            bytes  = "\x66\xb9" + pack("<H", const) # mov cx, const
                            bytes += "\x48\x0f\xb7\xc9"             # movzx rcx, cx

                        # 11 bytes
                        elif -2147483648 < const < 0:
                            bytes  = "\x48\x31\xc9"                 # xor rcx, rcx
                            bytes += "\x48\xFF\xC9"                 # dec rcx
                            bytes += "\xb9" + pack("<L", const)     # mov ecx, const

                        # 23 bytes
                        if "\x00" in bytes:
                            if const > 0:
                                packed = pack("<Q", const)
                            else:
                                packed = pack("<q", const)
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
                            bytes  = "\x48\xb8" + "".join(xored)    # mov rax, mask
                            bytes += "\x48\xb9" + "".join(mask)     # mov rcx, const ^ mask
                            bytes += "\x48\x31\xc1"                 # xor rcx, rax
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
        #        msg = "%s null check failed, size %.16X"
        #        print msg % (clazz.__name__, size)
        #        open("%s_%.16X.bin" % (clazz.__name__, size), "wb").write(bytes)
        #except Exception:
        #    msg = "%s failed with exception, size %.16X"
        #    print msg % (clazz.__name__, size)
        #    print traceback.format_exc()
        #    open("%s_%.16X.bin" % (clazz.__name__, size), "wb").write(bytes)

    def test_fail(clazz, size, nullfree = True):
        try:
            shellcode = clazz(size)
            if nullfree:
                state = CompilerState()
                state.shared["encoding"] = "nullfree"
                shellcode.compile(state)
            bytes = shellcode.bytes
            assert False
            #msg = "%s failed to raise exception, size %.16X"
            #print msg % (clazz.__name__, size)
            #open("%s_%.16X.bin" % (clazz.__name__, size), "wb").write(bytes)
        except Exception:
            pass

    test_fail(SubSP, 0x10000000000000000)
    test_fail(SubSP, -0x8000000000000001)

    test_ok(SubSP, 0xFFFFFFFFFFFFFFFF)
    test_ok(SubSP, 0x8000000000000000)
    test_ok(SubSP, 4294967296L)
    test_ok(SubSP, 4294967295L)
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

    test_fail(AllocaProbe,   0xFFFFFFFFFFFFFFFF * 0x1001)
    test_fail(AllocaProbe, -0x80000000000000000 * 0x1001)

    test_ok(AllocaProbe, -0x80000000000000000 * 0x1000)
    test_ok(AllocaProbe, -0x8000000000000001)
    test_ok(AllocaProbe, 0xFFFFFFFFFFFFFFFF * 0x1000)
    test_ok(AllocaProbe, 0x10000000000000000)
    test_ok(AllocaProbe, 0xFFFFFFFFFFFFFFFF)
    test_ok(AllocaProbe, 0x8000000000000000)
    test_ok(AllocaProbe, 4294967296L)
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
