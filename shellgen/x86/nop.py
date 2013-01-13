#!/usr/bin/env python

###############################################################################
## Nop sled x86 shellcode for ShellGen                                       ##
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

# TODO: randomized NOP sleds, encoding

class Nop (Dynamic):
    qualities = "no_stack, stack_balanced, preserve_registers"
    encoding  = "nullfree, lower, upper"

    def __init__(self, size = 1):
        self.size = size

    def compile(self, *argv, **argd):
        return "\x90" * self.size

#-----------------------------------------------------------------------------#

class Padder (Decorator):

    def __init__(self, child, size):
        super(Padder, self).__init__(child)
        self.size = size

    def compile(self, state):

        # Compile the child shellcode.
        self.child.compile(state)
        bytes = self.child.bytes

        # Get the "size" parameter.
        size = self.size

        # Get the total size we want to reach.
        total = abs(size)

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

    assert Nop(1).length == 1
    assert Nop(0x100).length == 0x100
    assert Nop(1).length == len(Nop(1).bytes)
    assert Nop(0x100).length == len(Nop(0x100).bytes)

    padder_right = Padder("<here goes the child>", 100)
    assert padder_right.length == len(padder_right.bytes)
    assert padder_right.length == 100
    assert padder_right.bytes.endswith("<here goes the child>")

    padder_left = Padder("<here goes the child>", -100)
    assert padder_left.length == len(padder_left.bytes)
    assert padder_left.length == 100
    assert padder_left.bytes.startswith("<here goes the child>")

    # These won't work when randomized nop sleds are supported.
    assert Nop(0x100).bytes == Nop(1).bytes * 0x100
    assert Nop(1).bytes == "\x90"
    assert Nop(0x100).bytes == "\x90" * 0x100
    assert Padder("<here goes the child>", 100).bytes == ("\x90" * 79) + "<here goes the child>"
    assert Padder("<here goes the child>", -100).bytes == "<here goes the child>" + ("\x90" * 79)
    assert Padder("<here goes the child>", 100).child.bytes == "<here goes the child>"
