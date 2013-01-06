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

__all__ = ["Nop", "Padder"]

# For unit testing always load this version, not the one installed.
if __name__ == '__main__':
    import sys, os.path
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from shellgen import Dynamic, Decorator

#------------------------------------------------------------------------------

# TODO: randomized NOP sleds, encoding

class Nop (Dynamic):
    encoding = "nullfree"

    def __init__(self, size = 1):
        self.size = size

    def compile(self, *argv, **argd):
        return "\x90" * self.size

#------------------------------------------------------------------------------

class Padder (Decorator):
    encoding = "nullfree"

    def __init__(self, child, size):
        super(Padder, self).__init__(child)
        self.size = size

    def compile(self, state):

        # Compile the child shellcode.
        bytes = self.compile_children(state)

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

        # If the "size" is a positive number, put the padding before the bytes.
        # If it's a negative number, put the padding after the bytes.
        if size < 0:
            bytes = bytes + pad
        else:
            bytes = pad + bytes

        # Return the bytecode.
        return bytes

#------------------------------------------------------------------------------

# Unit test.
if __name__ == '__main__':
    assert Nop(1).bytes == "\x90"
    assert Nop(0x100).bytes == "\x90" * 0x100
    assert Padder("<here goes the child>", 100).bytes == ("\x90" * 79) + "<here goes the child>"
    assert Padder("<here goes the child>", -100).bytes == "<here goes the child>" + ("\x90" * 79)
    assert Padder("<here goes the child>", 100).child.bytes == "<here goes the child>"
