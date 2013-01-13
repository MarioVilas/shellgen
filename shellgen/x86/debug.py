#!/usr/bin/env python

###############################################################################
## Various debug x86 shellcodes for ShellGen                                 ##
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
from ..base import Dynamic, Static

__all__ = ["Breakpoint", "While1"]

#-----------------------------------------------------------------------------#

class Breakpoint (Dynamic):
    qualities = "stack_balanced"
    encoding  = "nullfree"

    def __init__(self, size = 1):
        self.size = size

    def compile(self, *argv, **argd):
        return "\xcc" * self.size

class While1 (Static):
    qualities = "stack_balanced"
    encoding  = "nullfree"

    bytes  = "\xeb\xfe"  # jmp short $-2
    length = 2

#-----------------------------------------------------------------------------#

def test():
    "Unit test."
    assert Breakpoint.arch == "x86"
    assert Breakpoint.os == "any"
    assert While1.arch == "x86"
    assert While1.os == "any"
    assert While1().bytes == While1.bytes
    assert While1().length == While1.length
    assert Breakpoint(0x100).length == 0x100
    assert Breakpoint(0x100).bytes == Breakpoint(1).bytes * 0x100
