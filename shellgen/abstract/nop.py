#!/usr/bin/env python

###############################################################################
## Generic Nop sled shellcode for ShellGen                                   ##
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

"Nop sled."

from __future__ import absolute_import
from ..base import Dynamic, Decorator

__all__ = ["AbstractNop", "AbstractPadder"]

#-----------------------------------------------------------------------------#

class AbstractNop (Dynamic):
    qualities = "no_stack, stack_balanced, preserve_registers"

    # Subclasses define a string with the bytecode for a NOP instruction.
    @property
    def nop(self):
        raise NotImplementedError("This is an abstract class!")

    def __init__(self, size = None):
        if size is not None and size % len(self.nop) != 0:
            msg = "NOP sleds for %s must be aligned to %d bytes"
            msg = msg % (self.arch, len(self.nop))
            raise ValueError(msg)
        self.size = size

    def compile(self, *argv, **argd):
        size = self.size
        nop = self.nop
        if size is None:
            size = len(nop)
        elif size % len(nop) != 0:
            msg = "NOP sleds for %s must be aligned to %d bytes"
            msg = msg % (self.arch, len(nop))
            raise ValueError(msg)
        return nop * (size / len(nop))

#-----------------------------------------------------------------------------#

class AbstractPadder (Decorator):

    @property
    def Nop(self):
        raise NotImplementedError("This is an abstract class!")

    def __init__(self, child, size):
        super(AbstractPadder, self).__init__(child)
        if abs(size) % len(self.Nop.nop) != 0:
            msg = "NOP sleds for %s must be aligned to %d bytes"
            msg = msg % (self.arch, len(self.Nop.nop))
            raise ValueError(msg)
        self.size = size

    def compile(self, state):

        # Get the total size we want to reach.
        size  = self.size
        total = abs(size)
        if total % len(self.Nop.nop) != 0:
            msg = "NOP sleds for %s must be aligned to %d bytes"
            msg = msg % (self.arch, len(self.Nop.nop))
            raise ValueError(msg)

        # Compile the child shellcode.
        self.child.compile(state)
        bytes = self.child.bytes

        # If the child shellcode is too big, fail.
        if total < len(bytes):
            raise RuntimeError(
                "Child shellcode exceeds maximum size of %d" % total)

        # Make a NOP sled.
        nopsled = self.Nop( total - len(bytes) )
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

    try:
        AbstractNop().bytes
        assert False
    except NotImplementedError:
        pass

    try:
        AbstractPadder("AAAA", 8).bytes
        assert False
    except NotImplementedError:
        pass
