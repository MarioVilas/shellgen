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

"NOP sled."

from __future__ import absolute_import
from ..abstract.nop import AbstractNop, AbstractPadder

__all__ = ["Nop", "Padder"]

class Nop (AbstractNop):
    encoding = "nullfree, lower, upper"
    nop = "\x90"        # 90  nop

class Padder (AbstractPadder):
    Nop = Nop

# TODO: randomized NOP sleds, encoding

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

    assert Nop(0x100).bytes == Nop(1).bytes * 0x100
    assert Nop(1).bytes == "\x90"
    assert Nop(0x100).bytes == "\x90" * 0x100
    assert Padder("<here goes the child>", 100).bytes == ("\x90" * 79) + "<here goes the child>"
    assert Padder("<here goes the child>", -100).bytes == "<here goes the child>" + ("\x90" * 79)
    assert Padder("<here goes the child>", 100).child.bytes == "<here goes the child>"
