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

__all__ = ["Breakpoint", "While1"]

# For unit testing always load this version, not the one installed.
if __name__ == '__main__':
    import sys, os.path
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from shellgen import Dynamic, Static

#------------------------------------------------------------------------------

class Breakpoint (Dynamic):
    encoding = "nullfree"

    def __init__(self, size = 1):
        self.size = size

    def compile(self, *argv, **argd):
        return "\xcc" * self.size

class While1 (Static):
    encoding = "nullfree"
    bytes = "\xeb\xfe"  # jmp short $-2

#------------------------------------------------------------------------------

# Unit test.
if __name__ == '__main__':
    assert Breakpoint.arch == "x86"
    assert Breakpoint.os == "any"
    assert While1.arch == "x86"
    assert While1.os == "any"
    assert Breakpoint(1).bytes == "\xcc"
    assert Breakpoint(0x100).bytes == "\xcc" * 0x100
    assert While1().bytes == "\xeb\xfe"
