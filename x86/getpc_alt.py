#!/usr/bin/env python

###############################################################################
## Alternative GetPC x86 shellcode for ShellGen                              ##
## Based on idea by Skylined                                                 ##
## http://skypher.com/wiki/index.php/Hacking/Shellcode/GetPC                 ##
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

__all__ = ["GetPC_Alt"]

from shellgen import Dynamic

class GetPC_Alt (Dynamic):
    arch      = "x86"
    os        = None
    requires  = ()
    provides  = ("pc")
    qualities = ("nullfree")

    def __init__(self, pcreg = "ecx"):
        self.pcreg = pcreg

    def compile(self):
        pcreg = self.pcreg

        # This "call -1" instruction jumps on the last byte of itself, so the
        # next instruction uses an alternate encoding of the "dec" instruction
        # to decrement a harmless register.
        call_m1 = "\xEB\xFF\xFF\xFF\xFF"

        # Alternate encoding for "dec", the first byte must be \xFF.
        dec_alt = {
            "eax" : "\xC8",
            "ecx" : "\xC9",
            "edx" : "\xCA",
            "ebx" : "\xCB",
            "esp" : "\xCC",
            "ebp" : "\xCD",
            "esi" : "\xCE",
            "edi" : "\xCF",
        }

        # Pop the return address from the stack.
        pop = {
            "eax" : "\x58",
            "ecx" : "\x59",
            "edx" : "\x5A",
            "ebx" : "\x5B",
            "esp" : "\x5C",
            "ebp" : "\x5D",
            "esi" : "\x5E",
            "edi" : "\x5F",
        }

        # Adjust the return address by adding 5 to it.
        add_5 = {
            "eax" : "\x83\xC0\x05",
            "ecx" : "\x83\xC1\x05",
            "edx" : "\x83\xC2\x05",
            "ebx" : "\x83\xC3\x05",
            "ebp" : "\x83\xC4\x05",
            "esp" : "\x83\xC5\x05",
            "esi" : "\x83\xC6\x05",
            "edi" : "\x83\xC7\x05",
        }

        # Check the register name is valid.
        pcreg = pcreg.strip().lower()
        if not dec.has_key(pcreg):
            raise ValueError("Invalid target register: %s" % pcreg)

        # Build the shellcode.
        self._bytes = call_m1 + dec_alt[pcreg] + pop[pcreg] + add_5[pcreg]
