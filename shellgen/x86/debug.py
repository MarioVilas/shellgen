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

"Various debug shellcodes."

from __future__ import absolute_import
from ..base import Dynamic, Static

__all__ = ["Breakpoint", "While1", "Segfault", "StackOverflow"]

#-----------------------------------------------------------------------------#

class Breakpoint (Dynamic):
    "Trigger a software breakpoint interruption."

    qualities = "no_stack"
    encoding  = "nullfree"

    def __init__(self, size = 1):
        self.size = size

    def compile(self, *argv, **argd):
        return "\xcc" * self.size

class While1 (Static):
    "Infinite loop."

    qualities = "no_stack, payload" # execution stops here
    encoding  = "nullfree"

    bytes  = "\xeb\xfe" # jmp short $-2
    length = len(bytes)

class Segfault (Static):
    "Trigger a segmentation fault."

    qualities = "no_stack, payload" # execution stops here
    encoding  = "nullfree"

    bytes  = "\x31\xdb\x8b\x1b" # xor ebx, ebx / mov ebx, [ebx]
    length = len(bytes)

class StackOverflow (Static):
    """
    Crash the process by exhausting its stack space.

    On Windows this causes the process to die silently, without showing the
    application error message.
    """

    qualities = "payload"           # execution stops here
    encoding  = "nullfree"

    bytes  = "\x50\xeb\xfd" # push eax / jmp short $-3
    length = len(bytes)

#-----------------------------------------------------------------------------#

def test():
    "Unit test."
    assert Breakpoint.arch == "x86"
    assert Breakpoint.os == "any"
    assert While1.arch == "x86"
    assert While1.os == "any"
    assert Segfault.arch == "x86"
    assert Segfault.os == "any"
    assert StackOverflow.arch == "x86"
    assert StackOverflow.os == "any"
    assert While1().bytes == While1.bytes
    assert While1().length == While1.length
    assert len(While1().bytes) == While1().length
    assert Segfault().bytes == Segfault.bytes
    assert Segfault().length == Segfault.length
    assert len(Segfault().bytes) == Segfault().length
    assert StackOverflow().bytes == StackOverflow.bytes
    assert StackOverflow().length == StackOverflow.length
    assert len(StackOverflow().bytes) == StackOverflow().length
    assert Breakpoint(0x100).length == 0x100
    assert Breakpoint(0x100).bytes == Breakpoint(1).bytes * 0x100
