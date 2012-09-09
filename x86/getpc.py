#!/usr/bin/env python

###############################################################################
## GetPC x86 shellcode for ShellGen                                          ##
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

__all__ = ["GetPC"]

from shellgen import Dynamic

class GetPC (Dynamic):
    arch      = "x86"
    os        = None
    requires  = ()
    provides  = ("pc")
    qualities = ("nullfree")

    def __init__(self, pcreg = "ecx"):
        self.pcreg = pcreg

    def compile(self):
        pcreg = self.pcreg

        # Jump to the call instruction.
        jmp_f = "\xEB\x02"

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

        # Push it back again.
        push = {
            "eax" : "\x50",
            "ecx" : "\x51",
            "edx" : "\x52",
            "ebx" : "\x53",
            "esp" : "\x54",
            "ebp" : "\x55",
            "esi" : "\x56",
            "edi" : "\x57",
        }

        # Return to the contained shellcode.
        ret = "\xC3"

        # Call to the pop instruction.
        call_b += "\xE8\xF8\xFF\xFF\xFF"

        # Check the register name is valid.
        pcreg = pcreg.strip().lower()
        if not dec.has_key(pcreg):
            raise ValueError("Invalid target register: %s" % pcreg)

        # Build the shellcode.
        self._bytes = jmp_f + pop[pcreg] + push[pcreg] + ret + call_b[pcreg]
