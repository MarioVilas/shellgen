#!/usr/bin/env python

###############################################################################
## Nop sled MIPS shellcode for ShellGen                                      ##
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

__all__ = ["Nop", "Padder"]

#-----------------------------------------------------------------------------#

class Nop (Dynamic):
    qualities = "no_stack, stack_balanced, preserve_registers"

    def __init__(self, size = 4):
        if size & 3 != 0:
            raise ValueError("MIPS instructions are always 4 bytes in size")
        self.size = size

    def compile(self, *argv, **argd):
        if self.size & 3 != 0:
            raise ValueError("MIPS instructions are always 4 bytes in size")
        return "\x00" * self.size   # 00 00 00 00   sll r0, r0, 0

#-----------------------------------------------------------------------------#

class Padder (Decorator):

    def __init__(self, child, size):
        super(Padder, self).__init__(child)
        if abs(size) & 3 != 0:
            raise ValueError("MIPS instructions are always 4 bytes in size")
        self.size = size

    def compile(self, state):

        # Get the total size we want to reach.
        size  = self.size
        total = abs(size)
        if total & 3 != 0:
            raise ValueError("MIPS instructions are always 4 bytes in size")

        # Compile the child shellcode.
        self.child.compile(state)
        bytes = self.child.bytes

        # If the child shellcode is too big, fail.
        if total < len(bytes):
            raise RuntimeError(
                "Child shellcode exceeds maximum size of %d" % total)

        # Make a NOP sled.
        nopsled = Nop( total - len(bytes) )
        if size > 0:    # not in order anymore
            state.next_piece()
        nopsled.compile(state)
        pad = nopsled.bytes

        # If the pad goes before the bytes, relocate the child.
        if size > 0:
            self.child.relocate(len(pad))
            bytes = self.child.bytes

        # If the "size" is a positive number, put the padding before the bytes.
        # If it's a negative number, put the padding after the bytes.
        if size < 0:
            bytes = bytes + pad
        else:
            bytes = pad + bytes

        # Return the bytecode.
        return bytes

#-----------------------------------------------------------------------------#

def test():
    "Unit test."

    assert Nop(4).length == 4
    assert Nop(0x100).length == 0x100
    assert Nop(4).length == len(Nop(4).bytes)
    assert Nop(0x100).length == len(Nop(0x100).bytes)

    try:
        Nop(1)
        assert False
    except ValueError:
        pass
    try:
        nop = Nop(4)
        nop.size = 1
        nop.bytes
        assert False
    except ValueError:
        pass
    try:
        Padder("A" * 20, 101)
        assert False
    except ValueError:
        pass
    try:
        Padder("this is not aligned", 100).bytes
        assert False
    except ValueError:
        pass

    padder_right = Padder("A" * 20, 100)
    assert padder_right.length == len(padder_right.bytes)
    assert padder_right.length == 100
    assert padder_right.bytes.endswith("A" * 20)

    padder_left = Padder("A" * 20, -100)
    assert padder_left.length == len(padder_left.bytes)
    assert padder_left.length == 100
    assert padder_left.bytes.startswith("A" * 20)

    assert Nop(0x100).bytes == Nop(4).bytes * (0x100 / 4)
    assert Nop(4).bytes == "\x00\x00\x00\x00"
    assert Nop(0x100).bytes == "\x00" * 0x100
    assert Padder("A" * 20, 100).bytes == ("\x00" * 80) + ("A" * 20)
    assert Padder("A" * 20, -100).bytes == ("A" * 20) + ("\x00" * 80)
    assert Padder("A" * 20, 100).child.bytes == ("A" * 20)
