#!/usr/bin/env python

###############################################################################
## Adjust stack pointer x86-64 shellcode for ShellGen                        ##
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

__all__ = ["SubSP"]

import struct

from shellgen import Dynamic

"""
Disassembly of section .text:

0000000000000000 <.text>:
   0:	48 83 ec 01          	sub    rsp,0x1
   4:	48 83 ec ff          	sub    rsp,0xffffffffffffffff
   8:	48 81 ec 34 12 00 00 	sub    rsp,0x1234
   f:	48 81 ec cc ed ff ff 	sub    rsp,0xffffffffffffedcc
  16:	48 81 ec 78 56 34 12 	sub    rsp,0x12345678
  1d:	48 81 ec 88 a9 cb ed 	sub    rsp,0xffffffffedcba988
  24:	90                   	nop
  25:	48 83 c4 01          	add    rsp,0x1
  29:	48 83 c4 ff          	add    rsp,0xffffffffffffffff
  2d:	48 81 c4 34 12 00 00 	add    rsp,0x1234
  34:	48 81 c4 cc ed ff ff 	add    rsp,0xffffffffffffedcc
  3b:	48 81 c4 78 56 34 12 	add    rsp,0x12345678
  42:	48 81 c4 88 a9 cb ed 	add    rsp,0xffffffffedcba988
  49:	90                   	nop
  4a:	48 b8 21 43 65 87 78 	movabs rax,0x1234567887654321
  51:	56 34 12
  54:	48 29 c4             	sub    rsp,rax
  57:	48 01 c4             	add    rsp,rax
"""

class SubSP (Dynamic):
    encoding = "nullfree"

    def __init__(self, offset):
        self.offset = offset

    def compile(self, variables = None):
        offset = self.offset
        pack = struct.pack
        if -128 <= offset <= 127:
            bytes = "\x48\x83\xEC" + pack("=b", offset)
        elif -2147483648 <= offset <= 2147483647:
            bytes = "\x48\x81\xEC" + pack("<l", offset)
        else:
            bytes = "\x48\xb8" + pack("<q", offset) + "\x48\x29\xC4"
        if "\x00" in bytes:
            if -128 <= offset <= 127:
                bytes = "\x48\x83\xC4" + pack("=b", -offset)
            elif -2147483648 <= offset <= 2147483647:
                bytes = "\x48\x81\xC4" + pack("<l", -offset)
            else:
                bytes = "\x48\xb8" + pack("<q", offset) + "\x48\x01\xC4"
        self._bytes = bytes
        if "\x00" in bytes:
            self.remove_encoding("nullfree")
        else:
            self.add_encoding("nullfree")
