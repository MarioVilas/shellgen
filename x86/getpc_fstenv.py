#!/usr/bin/env python

###############################################################################
## FSTENV GetPC x86 shellcode for ShellGen                                   ##
## Based on original idea by Skylined                                        ##
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

__all__ = ["GetPC_FSTENV"]

from shellgen import Dynamic

# Note: this shellcode may be hard to single-step on because it uses the stack
# space at negative ESP offsets, which is overwritten by some debuggers.

# $+0  D9EE       FLDZ                ; Floating point stores $+0 in its environment
# $+2  D974E4 F4  FSTENV SS:[ESP-0xC] ; Save environment at ESP-0xC; now [ESP] = $+0
# $+6  59         POP ECX             ; ECX = $+0
# $+7  83E9 F2    SUB ECX, -10        ; ECX = $+10
# $+10 ...

class GetPC_FSTENV (Dynamic):
    arch      = "x86"
    os        = None
    requires  = ()
    provides  = ("pc")
    qualities = ("nullfree")

    def __init__(self, pcreg = "ecx"):
        self.pcreg = pcreg

    def compile(self):
        pcreg = self.pcreg

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

        # It's actually sub -10 to avoid using \x0A (more parser friendly).
        add_10 = {
            "eax" : "\x83\xE8\xF2",
            "ecx" : "\x83\xE9\xF2",
            "edx" : "\x83\xEA\xF2",
            "ebx" : "\x83\xEB\xF2",
            "ebp" : "\x83\xEC\xF2",
            "esp" : "\x83\xED\xF2",
            "esi" : "\x83\xEE\xF2",
            "edi" : "\x83\xEF\xF2",
        }

        # Check the register name is valid.
        if not pop.has_key(pcreg):
            raise ValueError("Invalid target register: %s" % pcreg)

        self._bytes = "\xD9\xEE\xD9\x74\xE4\xF4" + pop[pcreg] + add_10[pcreg]
