#!/usr/bin/env python

###############################################################################
## EICAR test shellcode for ShellGen                                         ##
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

"EICAR test."

from __future__ import absolute_import
from ..base import Static

__all__ = ["EICAR"]

class EICAR (Static):
    """
    The EICAR test string is a standard way of testing antivirus software.
    This shellcode can be used to test the antivirus of a target machine,
    or an IDS between your machine and the target.

    Anecdotically, the string also happens to be a valid DOS executable file.

    For more details see: U{https://en.wikipedia.org/wiki/EICAR_test_file}
    """

    qualities = "payload"
    encoding  = "nullfree"
    bytes     = "X5O!P%@AP[4\PZX54(P^)7CC)7}$"       + \
                "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" + \
                "!$H+H*"
