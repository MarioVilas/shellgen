#!/usr/bin/env python

###############################################################################
## Kill the current process on Linux/x86                                     ##
## Shellcode for ShellGen                                                    ##
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

__all__ = ["Exit"]

from shellgen import Static

class Exit (Static):
    qualities = ("payload", "stack_balanced")
    encoding  = "nullfree"

    def __init__(self, exitcode = None):

        # with exitcode: 7 ~ 8 bytes.
        # without exitcode: 5 bytes.

        bytes  = "\x6a\x01"                             # push 0x01
        bytes += "\x58"                                 # pop eax

        if exitcode is not None:
            if exitcode == 0:
                bytes += "\x31\xdb"                     # xor ebx, ebx
            else:
                bytes += "\x6a" + pack("b", exitcode)   # push exitcode
                bytes += "\x5b"                         # pop ebx

        bytes += "\xcd\x80"                             # int 0x80

        self.bytes = bytes
