#!/usr/bin/env python

###############################################################################
## Adjust stack pointer x86 shellcode for ShellGen                           ##
###############################################################################

# Copyright (c) 2012 Mario Vilas
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

__all__ = ["SubSP"]

import struct

from shellgen import Dynamic

"""
Disassembly of section .text:

00000000 <.text>:
   0:	83 ec 01             	sub    esp,0x1
   3:	83 ec ff             	sub    esp,0xffffffff
   6:	81 ec 34 12 00 00    	sub    esp,0x1234
   c:	81 ec cc ed ff ff    	sub    esp,0xffffedcc
  12:	81 ec 78 56 34 12    	sub    esp,0x12345678
  18:	81 ec 88 a9 cb ed    	sub    esp,0xedcba988
  1e:	83 c4 01             	add    esp,0x1
  21:	83 c4 ff             	add    esp,0xffffffff
  24:	81 c4 34 12 00 00    	add    esp,0x1234
  2a:	81 c4 cc ed ff ff    	add    esp,0xffffedcc
  30:	81 c4 78 56 34 12    	add    esp,0x12345678
  36:	81 c4 88 a9 cb ed    	add    esp,0xedcba988
"""

class SubSP (Dynamic):
    arch      = "x86"
    os        = None
    requires  = ()
    provides  = ()
    qualities = ("nullfree")

    def __init__(self, offset):
        self.offset = offset

    def compile(self):
        offset = self.offset
        pack = struct.pack
        if -128 <= offset <= 127:
            bytes = "\x83\xEC" + pack("=b", offset)
        else:
            bytes = "\x81\xEC" + pack("<l", offset)
        if "\x00" in bytes:
            if -128 <= offset <= 127:
                bytes = "\x83\xC4" + pack("=b", -offset)
            else:
                bytes = "\x81\xC4" + pack("<l", -offset)
            if "\x00" in bytes:
                msg = "Can't compute null free %s(%s)"
                msg = msg % (self.__class__.__name__, hex(offset))
                raise ArithmeticError(msg)
        self._bytes = bytes
