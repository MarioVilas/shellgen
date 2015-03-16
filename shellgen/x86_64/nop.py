#!/usr/bin/env python

###############################################################################
## Nop sled x86-64 shellcode for ShellGen                                    ##
###############################################################################

# Copyright (c) 2012-2015 Mario Vilas
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

"NOP sled."

from __future__ import absolute_import
from ..x86.nop import *
from ..x86.nop import __all__
from ..base import copy_classes
copy_classes(__all__, __name__, vars())
