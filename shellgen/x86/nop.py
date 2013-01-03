#!/usr/bin/env python

###############################################################################
## Nop sled x86 shellcode for ShellGen                                       ##
###############################################################################

# Copyright (c) 2012-2013 Mario Vilas
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

__all__ = ["Nop"]

from shellgen import Dynamic

class Nop (Dynamic):
    encoding = "nullfree"

    def __init__(self, size = 1):
        self.size = size

    def compile(self, variables = None):
        self._bytes = "\x90" * self.size

# TODO: randomized NOP sleds, encoding
