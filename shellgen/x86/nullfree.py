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

        # If we can't, try again with a variable size XOR key.
        except EncodingError:

            # Remember we failed with 8 bits so we don't try next time.
            self.__try_8_bit = False

            # For each possible key size...
            key_size = 4
            while 1:
                try:

                    # Align the child shellcode size.
                    child_bytes = self.align(child_bytes, key_size)

                    # Calculate a XOR key.
                    key = self.find_key(child_bytes, key_size)

                    # Compile the decoder stub.
                    decoder, key_deltas = self.get_decoder(key)

                    # Relocate the child.
                    delta = len(prefix) + len(decoder) - delta
                    if delta:
                        child.relocate(delta)

                        # Align the relocated child shellcode size to 32 bits.
                        relocated_child_bytes = self.align(
                                                        relocated_child_bytes,
                                                        key_size)

                        # Did the child change due to relocation?
                        relocated_child_bytes = child.bytes
                        if relocated_child_bytes != child_bytes:

                            # Remember the child is position dependent.
                            self._position_dependent = True

                            # Recalculate the XOR key.
                            key = self.find_key(child_bytes, key_size)

                            # Patch the decoder stub.
                            decoder = patch_decoder(decoder, key_deltas, key)

                            # Use the relocated child bytes.
                            child_bytes = relocated_child_bytes

                    # We've done it! Break out of the loop.
                    break

                # We failed, there's no valid key for this size.
                except EncodingError:

                    # Try again with a bigger key.
                    # TODO: Maybe allow the decoder to have non-aligned keys?
                    key_size += 4

                    # The key can't be larger than the child shellcode.
                    # (FIXME: It could be equal, but that would make a very
                    # inefficient decoder stub. Another algorithm would be
                    # needed for pathological cases - then we'll measure the
                    # size of the decoder stub + the child shellcode instead.)
                    if key_size > len(child_bytes):
                        raise

            # XOR-encode the bytes.
            child_bytes = self.encode(child_bytes, key)

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

        # Pick any character that's not present in the shellcode.
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
        # XXX TODO
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
    def align(bytes, key_size):
        """
        Pad the bytecode with NOP instructions to a align its size to n bytes.

        @type  bytes: str
        @param bytes: Bytecode to align.

        @type  key_size: int
        @param key_size: Byte size to align the shellcode to.

        @rtype:  str
        @return: Aligned bytecode.
        """
        tail = len(bytes) % key_size
        if tail:
            bytes += "\x90" * (key_size - tail)
        return bytes

    @staticmethod
    def find_key(bytes, key_size):
        """
        Find a suitable n-byte XOR key for the given bytecode.

        @type  bytes: str
        @param bytes: Bytecode to encode. Its size must be aligned to n bytes.

        @type  key_size: int
        @param key_size: Size of the key, in bytes.

        @rtype:  str
        @return: n-byte XOR key, packed as a string.
        """

        # Precalculate the range of possible keysize-relative positions.
        key_range = range(key_size)

        # Find the keysize-relative position of all characters.
        position = tuple([set() for _ in key_range])
        for index in xrange(len(bytes)):
            char = bytes[index]
            position[index & 3].add(char)

        # For each keysize-relative position find the characters that are NOT
        # there, from those pick any character, and combine it into the key.
        # If there are no candidates for this position, then there's no valid
        # key for this size.
        key = ""
        all = set(key_range)
        randint = random.randint
        for index in key_range:
            candidates = position[index]
            candidates.difference_update(all)
            if not candidates:
                raise EncodingError()
            key += tuple(candidates)[randint(0, len(candidates))]

        # Return the key.
        return key

    @staticmethod
    def get_decoder(key):
        """
        Get the decoder stub bytecode for the variable size XOR algorithm.

        @type  key: str
        @param key: XOR key.

        @rtype:  str
        @return: Decoder stub bytecode.
        """

        #
        # XXX TODO
        #

    @staticmethod
    def encode(bytes, key):
        """
        Encode the bytecode with the given variable size XOR key.

        @type  bytes: str
        @param bytes: Bytecode to encode.
            Its size must be aligned to the size of the key.

        @type  key: str
        @param key: XOR key.

        @rtype:  str
        @return: Encoded bytecode.

        @raise ValueError:
            The bytecode size must be aligned to the size of the key.
        """
        if len(bytes) % len(key):
            raise ValueError(
                "The bytecode size must be aligned to the size of the key.")
        pad = key * (len(bytes) / len(key))
        # TODO: Maybe using pack and unpack is faster? Benchmark!
        return "".join(
            [ chr( ord(bytes[i]) ^ ord(pad[i]) ) for i in xrange(len(bytes)) ]
        )

#-----------------------------------------------------------------------------#

def test():
    pass
