#!/usr/bin/env python

###############################################################################
## Null-free encoder x86 shellcode for ShellGen                              ##
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

from __future__ import absolute_import
from ..base import Encoder, EncodingError
from ..util import bit_length, compile_child
from .getpc import GetPC

import struct
import random
import warnings
import collections

__all__ = ["NullFreeEncoder"]

#-----------------------------------------------------------------------------#

class NullFreeEncoder (Encoder):
    encoding = "nullfree"

    def __init__(self, child):
        super(NullFreeEncoder, self).__init__(child)
        self.__position_dependent = False
        self.__try_8_bit = True

    def clear(self):
        super(NullFreeEncoder, self).clear()
        self.__position_dependent = False
        self.__try_8_bit = True

    def relocate(self, delta):
        if delta != 0 and self.__position_dependent:
            raise NotImplementedError() # you're asking too much :)

    def compile(self, state):

        # Assume the child is position independent until we prove otherwise.
        self.__position_dependent = False

        # Get the child shellcode.
        child = self.child

        # Get the register that contains the current value of EIP.
        pc = state.previous.get("pc", None)

        # Compile the child shellcode and get its bytes.
        child_bytes = compile_child(child, state)

        # If no null characters are present, just return the child bytes.
        if "\x00" not in child_bytes:
            return child_bytes

        # If a PC register was not given, prepend a GetPC automatically.
        prefix = ""
        if not pc:
            getpc  = GetPC()
            prefix = getpc.bytes
            pc     = getpc.pcreg

        # Try encoding with an 8-bit XOR key first.
        delta = 0
        try:

            # Don't try if the last time we compiled it failed.
            if not self.__try_8_bit:
                raise EncodingError()

            # Calculate a XOR key.
            key = self.find_key_8(child_bytes)

            # Compile the decoder stub.
            decoder, key_delta = self.get_decoder_8(key)

            # Relocate the child.
            delta = len(prefix) + len(decoder)
            child.relocate(delta)

            # Did the child change due to relocation?
            relocated_child_bytes = child.bytes
            if relocated_child_bytes != child_bytes:

                # Remember the child is position dependent.
                self._position_dependent = True

                # Recalculate the XOR key.
                key = self.find_key_8(relocated_child_bytes)

                # Patch the decoder stub.
                decoder = patch_decoder_8(decoder, key_delta, key)

                # Use the relocated child bytes.
                child_bytes = relocated_child_bytes

            # XOR-encode the bytes.
            child_bytes = self.encode_8(child_bytes, key)

        # If we can't, try again with a 32-bit XOR key.
        except EncodingError:

            # Remember we failed with 8 bits so we don't try next time.
            self.__try_8_bit = False

            # Align the child shellcode size to 32 bits.
            child_bytes = self.align_32(child_bytes)

            # Calculate a XOR key.
            key = self.find_key_32(child_bytes)

            # Compile the decoder stub.
            decoder, key_delta = self.get_decoder_32(key)

            # Relocate the child.
            delta = len(prefix) + len(decoder) - delta
            if delta:
                child.relocate(delta)

                # Align the relocated child shellcode size to 32 bits.
                relocated_child_bytes = self.align_32(relocated_child_bytes)

                # Did the child change due to relocation?
                relocated_child_bytes = child.bytes
                if relocated_child_bytes != child_bytes:

                    # Remember the child is position dependent.
                    self._position_dependent = True

                    # Recalculate the XOR key.
                    key = self.find_key_32(child_bytes)

                    # Patch the decoder stub.
                    decoder = patch_decoder_32(decoder, key_delta, key)

                    # Use the relocated child bytes.
                    child_bytes = relocated_child_bytes

            # XOR-encode the bytes.
            child_bytes = self.encode_32(child_bytes, key)

        # Return the decoder stub + the encoded bytes.
        return prefix + decoder + child_bytes

    @staticmethod
    def find_key_8(bytes):
        """
        Find a suitable 8-bit XOR key for the given bytecode.

        @type  bytes: str
        @param bytes: Bytecode to encode. Its size must be aligned to 32 bits.

        @rtype:  int
        @return: 8-bit XOR key.
        """

        # Pick a random character that's not present in the shellcode.
        used_chars = {ord(char) for char in bytes}
        free_chars = set(xrange(256))
        free_chars.difference_update(used_chars)
        if not free_chars:
            raise EncodingError()
        candidates = list(free_chars)
        return candidates[ random.randint(0, len(candidates) - 1) ]

    @staticmethod
    def get_decoder_8(key):
        """
        Get the decoder stub bytecode for the 8-bit XOR algorithm.

        @type  key: int
        @param key: 8-bit XOR key.

        @rtype:  str
        @return: Decoder stub bytecode.
        """

        #
        # TODO
        #

    @staticmethod
    def encode_8(bytes, key):
        """
        Encode the bytecode with the given 8-bit XOR key.

        @type  bytes: str
        @param bytes: Bytecode to encode. Its size must be aligned to 32 bits.

        @type  key: int
        @param key: 8-bit XOR key.

        @rtype:  str
        @return: Encoded bytecode.
        """
        return "".join( ( chr(ord(c) ^ key) for c in bytes ) )

    @staticmethod
    def align_32(bytes):
        """
        Pad the bytecode with NOP instructions to a align its size to 32 bits.

        @type  bytes: str
        @param bytes: Bytecode to align.

        @rtype:  str
        @return: Aligned bytecode.
        """
        if len(bytes) & 3:
            bytes += "\x90" * (3 - (len(bytes) & 3))
        return bytes

    @staticmethod
    def find_key_32(bytes):
        """
        Find a suitable 32-bit XOR key for the given bytecode.

        @type  bytes: str
        @param bytes: Bytecode to encode. Its size must be aligned to 32 bits.

        @rtype:  int
        @return: 32-bit XOR key.
        """

        # Get the frequency and DWORD-relative position of all characters.
        frequency = collections.defaultdict(int)
        position  = collections.defaultdict(set)
        for index in xrange(len(bytes)):
            char = bytes[index]
            frequency[char] += 1
            position[char].add( index & 3 )
        frequency = dict(frequency)
        position  = dict(position)

        # Remove 0 and all characters that appear in all 4 positions, and
        # convert the positions occupied into available.
        try:
            del frequency["\x00"]
            del position["\x00"]
        except KeyError:
            pass    # should never happen...
        all_positions = {0, 1, 2, 3}
        for char, pos in position.keys():
            if len(pos) == 4:
                del frequency[char]
                del position[char]
            else:
                position[char].difference_update(all_positions)

        # Sort the candidate characters, the least likely to appear goes first.
        candidates = [ (y, x) for (x, y) in frequency.iteritems() ]
        candidates.sort()
        candidates = [ t[0] for t in candidates ]

        # Try picking all possible combinations until one is valid.

        #
        # TODO
        #

        # If there's no valid combination, fail with an exception.
        raise EncodingError()

    @staticmethod
    def get_decoder_32(key):
        """
        Get the decoder stub bytecode for the 32-bit XOR algorithm.

        @type  key: int
        @param key: 32-bit XOR key.

        @rtype:  str
        @return: Decoder stub bytecode.
        """

        #
        # TODO
        #

    @staticmethod
    def encode_32(bytes, key):
        """
        Encode the bytecode with the given 32-bit XOR key.

        @type  bytes: str
        @param bytes: Bytecode to encode. Its size must be aligned to 32 bits.

        @type  key: int
        @param key: 32-bit XOR key.

        @rtype:  str
        @return: Encoded bytecode.
        """
        if len(bytes) & 3:
            raise ValueError("The bytecode size must be aligned to 32 bits")
        if bit_length(key) > 32:
            raise ValueError("The XOR key must fit in 32 bits")
        pack = struct.pack
        unpack = struct.unpack
        return "".join(
            (pack("<L", unpack("<L", bytes[i:i+4])[0] ^ key)
             for i in xrange(0, len(bytes), 4))
        )

#-----------------------------------------------------------------------------#

def test():
    pass
