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
    encoding  = "nullfree"
    qualities = "stack_balanced"

    # Bytecode for the 8-bit XOR decoder stub (12 bytes).
    __decoder_stub_8 = (
        "\x83\xC6\x0B"  # decoder: add esi, byte payload - 1
        "\x46"          # decrypt: inc esi
        "\x80\x36\xFF"  #          xor byte [esi], 255  ; key
        "\x80\x3e\xFE"  #          cmp byte [esi], 254  ; terminator
        "\x75\xF7"      #          jnz decrypt
                        # payload: ; encoded bytes go here
    )

    # Delta offset where to patch the 8-bit XOR decoder stub to set the key.
    __decoder_stub_delta_key_8 = 6

    # Delta where to patch the 8-bit XOR decoder stub to set the terminator.
    __decoder_stub_delta_terminator_8 = 9

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
            getpc  = GetPC(pcreg = "esi")
            prefix = getpc.bytes
            pc     = getpc.pcreg

        # The decoder stub expects the PC register to be ESI.
        # XXX FIXME: the stub could use another reg instead of doing this!
        if not pc:
            raise CompileError("Invalid PC register: %r" % pc)
        pc = pc.strip().lower()
        if pc != "esi":
            push = {
                "eax" : "\x50",     # push eax
                "ecx" : "\x51",     # push ecx
                "edx" : "\x52",     # push edx
                "ebx" : "\x53",     # push ebx
                "esp" : "\x54",     # push esp
                "ebp" : "\x55",     # push ebp
                "esi" : "\x56",     # push esi
                "edi" : "\x57",     # push edi
            }
            if pc not in push:
                raise CompileError("Invalid PC register: %r" % pc)
            prefix += push[pc] + "\x5E" # push reg32 / pop esi

        # Try encoding with an 8-bit XOR key first.
        delta = 0
        try:

            # Don't try if the last time we compiled it failed.
            if not self.__try_8_bit:
                raise EncodingError()

            # Calculate a XOR key.
            key, terminator = self.find_key_8(child_bytes)

            # Compile the decoder stub.
            decoder = self.get_decoder_8(key, terminator)

            # Relocate the child.
            delta = len(prefix) + len(decoder)
            child.relocate(delta)

            # Did the child change due to relocation?
            relocated_child_bytes = child.bytes
            if relocated_child_bytes != child_bytes:

                # Use the relocated child bytes.
                child_bytes = relocated_child_bytes

                # Remember the child is position dependent.
                self._position_dependent = True

                # Recalculate the XOR key.
                key, terminator = self.find_key_8(child_bytes)

                # Recompile the decoder stub.
                decoder = self.get_decoder_8(key, terminator)

            # XOR-encode the bytes.
            child_bytes = self.encode_8(child_bytes, key, terminator)

        # If we can't, try again with a variable size XOR key.
        except EncodingError:

            # Remember we failed with 8 bits so we don't try next time.
            self.__try_8_bit = False

            # For each possible key size, starting with one DWORD...
            key_size = 4
            while 1:
                try:

                    # Align the child shellcode size.
                    child_bytes = self.align(child_bytes, key_size)

                    # Calculate a XOR key.
                    key = self.find_key(child_bytes, key_size)

                    # Calculate a terminator token.
                    terminator = self.find_terminator(child_bytes)

                    # Compile the decoder stub.
                    decoder, key_deltas, term_delta = self.get_decoder(key,
                                                                    terminator)

                    # Relocate the child.
                    delta = len(prefix) + len(decoder) - delta
                    if delta:
                        child.relocate(delta)
                        relocated_child_bytes = child.bytes

                        # Align the relocated child shellcode size.
                        relocated_child_bytes = self.align(
                                                        relocated_child_bytes,
                                                        key_size)

                        # Did the child change due to relocation?
                        if relocated_child_bytes != child_bytes:

                            # Use the relocated child bytes.
                            child_bytes = relocated_child_bytes

                            # Remember the child is position dependent.
                            self._position_dependent = True

                            # Recalculate the XOR key.
                            key = self.find_key(child_bytes, key_size)

                            # Recalculate the terminator token.
                            terminator = self.find_terminator(child_bytes)

                            # Patch the decoder stub.
                            decoder = patch_decoder(decoder,
                                                    key_deltas, key,
                                                    term_delta, terminator)

                    # We've done it! Break out of the loop.
                    break

                # We failed, there's no valid key for this size.
                except EncodingError:

                    # Try again with a bigger key. Keys must be aligned
                    # to DWORD because the decoder stub requires it so.
                    key_size += 4

                    # The key can't be larger than the child shellcode.
                    if key_size > len(child_bytes):
                        raise

            # XOR-encode the bytes.
            child_bytes = self.encode(child_bytes, key, terminator)

        # Return the decoder stub + the encoded bytes.
        bytes = prefix + decoder + child_bytes
        if "\x00" in bytes:
            raise EncodingError("Internal error!")
        return bytes

    @classmethod
    def get_decoder_8(cls, key, terminator):
        """
        Get the decoder stub bytecode for the 8-bit XOR algorithm.

        @type  key: str
        @param key: XOR key.

        @type  terminator: str
        @param terminator: 8-bit terminator.

        @rtype:  str
        @return: Decoder stub bytecode.
        """
        delta_key = cls.__decoder_stub_delta_key_8
        delta_term = cls.__decoder_stub_delta_terminator_8
        decoder = cls.__decoder_stub_8
        decoder = decoder[:delta_key]  + key        + decoder[ delta_key+1:]
        decoder = decoder[:delta_term] + terminator + decoder[delta_term+1:]
        return decoder

    @staticmethod
    def find_key_8(bytes):
        """
        Find a suitable 8-bit XOR key for the given bytecode.

        @type  bytes: str
        @param bytes: Bytecode to encode. Its size must be aligned to 32 bits.

        @rtype:  tuple(str, str)
        @return: 8-bit XOR key, and 8-bit terminator.
        """

        # Pick any character that's not present in the shellcode.
        used_chars = set(bytes)
        free_chars = set( struct.pack("B" * 254, *range(1, 255)) )
        free_chars.difference_update(used_chars)
        if len(free_chars) < 2:
            raise EncodingError()
        candidates = list(free_chars)
        key = candidates[ random.randint(0, len(candidates) - 1) ]
        candidates.remove(key)
        terminator = candidates[ random.randint(0, len(candidates) - 1) ]
        return key, terminator

    @staticmethod
    def encode_8(bytes, key, terminator):
        """
        Encode the bytecode with the given 8-bit XOR key.

        @type  bytes: str
        @param bytes: Bytecode to encode.

        @type  key: str
        @param key: 8-bit XOR key.

        @type  terminator: str
        @param terminator: 8-bit terminator.

        @rtype:  str
        @return: Encoded bytecode.
        """
        bytes += terminator
        fmt = "B" * len(bytes)
        unpack = struct.unpack
        pad = unpack("B", key) * len(bytes)
        bytes = unpack(fmt, bytes)
        bytes = [ bytes[i] ^ pad[i] for i in xrange(len(bytes)) ]
        return struct.pack(fmt, *bytes)

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
        @param bytes: Bytecode to encode.
            Must be at least C{key_size} bytes long.

        @type  key_size: int
        @param key_size: Size of the key, in bytes.

        @rtype:  str
        @return: n-byte XOR key, packed as a string.
        """

        # Precalculate the range of possible keysize-relative positions.
        key_range = range(key_size)

        # Find the keysize-relative position of all characters,
        # except for the null character.
        position = tuple([set() for _ in key_range])
        for index in xrange(len(bytes)):
            char = bytes[index]
            if char != "\x00":
                position[index % key_size].add(char)

        # For each keysize-relative position find the characters that are NOT
        # there, from those pick any character, and combine it into the key.
        # If there are no candidates for this position, then there's no valid
        # key for this size.
        randint = random.randint
        key = ""
        all = set( struct.pack("B" * 254, *xrange(1, 255)) )
        for index in key_range:
            candidates = position[index]
            candidates.symmetric_difference_update(all)
            if not candidates:
                raise EncodingError()
            key += tuple(candidates)[ randint(0, len(candidates) - 1) ]

        # Return the key.
        return key

    @staticmethod
    def find_terminator(bytes):
        """
        Find a suitable terminator token.

        @type  bytes: str
        @param bytes: Bytecode to encode.

        @rtype:  str
        @return: DWORD terminator token, packed as a string.
        """

        # If we're lucky, we may use four nulls as the terminator.
        # This allows an optimization in the decoder stub.
        # For that we must make sure we don't have four aligned nulls in the
        # bytecode, because that would terminate the decoding loop prematurely.
        if "\0\0\0\0" not in ( bytes[i:i+4] for i in xrange(len(bytes)) ):
            return "\0\0\0\0"

        # Just find any random DWORD that's not present in the bytecode,
        # avoiding null characters so we can use it verbatim in the stub.
        # The only way this can fail is with a >16Gb string containing
        # all possible combinations, so I'm pretty confident we'll never
        # actually come across that corner case in real life. :)
        randint = random.randint
        pack    = struct.pack
        while True:
            terminator = pack("BBBB", *(randint(1,255), randint(1,255),
                                        randint(1,255), randint(1,255)))
            if terminator not in bytes:
                return terminator

    @staticmethod
    def get_decoder(key, terminator):
        """
        Get the decoder stub bytecode for the variable size XOR algorithm.

        @type  key: str
        @param key: XOR key. Must be aligned to DWORD.

        @type  terminator: str
        @param terminator: Terminator token. Must be a DWORD.

        @rtype:  tuple(str, list(int), int)
        @return: Tuple containing the decoder stub bytecode, the list of
            delta offsets to patch if the XOR key needs to be replaced,
            and the delta offset to patch if the terminator token needs to
            be replaced.

        @raise ValueError: The key size is not aligned to DWORD,
            or the terminator token is not a DWORD.
        @raise EncodingError: The decoder stub could not be compiled.
        """
        if len(key) & 3:
            msg = "Key size must be aligned to 4 bytes, got %d"
            raise ValueError(msg % len(key))
        if len(terminator) != 4:
            msg = "Terminator token must be 4 bytes in size, got %d"
            raise ValueError(msg % len(terminator))
        try:
            if terminator == "\x00\x00\x00\x00":

                # ; 14 bytes, +7 per extra DWORD in the key
                # decoder: add esi, byte payload
                #          mov edi, esi
                # decrypt: lodsd
                #          xor eax, 0xBAADF00D ; XOR key
                #          stosd
                #          ; insert more LODSD/XOR/STOSD here...
                #          jnz decrypt  ; terminator is hardcoded to four nulls
                # payload: ; encoded bytes go here

                pack = struct.pack
                decoder = ("\x83\xC6" + pack("B", 13 + (len(key) >> 2)) +
                           "\x89\xF7"
                           "\xAD")
                key_deltas = []
                for i in xrange(0, len(key), 4):
                    key_deltas.append(len(decoder) + 1)
                    decoder += "\x35" + key[i:i+4]
                decoder += ("\xAB"
                            "\x75" + pack("b", -8 - (len(key) >> 2)))
                return decoder, key_deltas, None

            else:

                # ; 19 bytes, +7 per extra DWORD in the key
                # decoder: add esi, byte payload
                #          mov edi, esi
                # decrypt: lodsd
                #          xor eax, 0xBAADF00D ; XOR key
                #          ; insert more XORs here, patch the ADD ESI above
                #          stosd
                #          cmp eax, 0xDEADBEEF ; terminator
                #          jnz decrypt
                # payload: ; encoded bytes go here

                pack = struct.pack
                decoder = ("\x83\xC6" + pack("B", 18 + (len(key) >> 2)) +
                           "\x89\xF7"
                           "\xAD")
                key_deltas = []
                for i in xrange(0, len(key), 4):
                    key_deltas.append(len(decoder) + 1)
                    decoder += "\x35" + key[i:i+4]
                decoder += ("\xAB\x3D" + terminator +
                            "\x75" + pack("b", -13 - (len(key) >> 2)))
                return decoder, key_deltas, len(decoder) - 6

        except struct.error:
            raise EncodingError("The decoder stub could not be compiled.")

    @staticmethod
    def encode(bytes, key, terminator):
        """
        Encode the bytecode with the given variable size XOR key.

        @type  bytes: str
        @param bytes: Bytecode to encode.

        @type  key: str
        @param key: XOR key.

        @type  terminator: str
        @param terminator: Terminator token. Must be a DWORD.

        @rtype:  str
        @return: Encoded bytecode.
        """
        bytes += terminator
        unpack = struct.unpack
        fmt = "B" * len(bytes)
        bytes = unpack(fmt, bytes)
        key = unpack("B" * len(key), key)
        pad_size = len(bytes) / len(key)
        if len(bytes) % len(key):
            pad_size += 1
        pad = key * pad_size
        bytes = [ bytes[i] ^ pad[i] for i in xrange(len(bytes)) ]
        return struct.pack(fmt, *bytes)

    @staticmethod
    def patch_decoder(decoder, key_deltas, key, terminator_delta, terminator):
        """
        Patch the decoder stub to change the XOR key.

        @type  decoder: str
        @param decoder: Decoder stub bytecode to be patched.

        @type  key_deltas: list(int)
        @param key_deltas:
            List of delta offsets to patch to replace the XOR key.

        @type  key: str
        @param key: XOR key.

        @type  terminator_delta: int
        @param terminator_delta:
            Delta offset to patch to replace the terminator token.
            If C{None} the terminator token is not changed.

        @type  terminator: str
        @param terminator: Terminator token.
            Only required if C{terminator_delta} is not C{None}.

        @rtype:  str
        @return: Patched decoded stub that uses the new key and token.

        @raise ValueError: The key size is not aligned to DWORD,
            the terminator token is not a DWORD, or the number of key
            deltas doesn't match the key length.
        """
        if len(key) & 3:
            msg = "Key size must be aligned to 4 bytes, got %d"
            raise ValueError(msg % len(key))
        if len(key_deltas) != (len(key) >> 2):
            msg = "Key size is %d bytes, got %d deltas"
            raise ValueError(msg % (len(key), len(key_deltas)))
        for i in xrange(len(key_deltas)):
            delta = key_deltas[i]
            fragment = key[ i << 2 : (i + 1) << 2 ]
            decoder = decoder[ : delta ] + fragment + decoder[ delta + 4 : ]
        if terminator_delta is not None:
            if len(terminator) != 4:
                msg = "Terminator token must be 4 bytes in size, got %d"
                raise ValueError(msg % len(terminator))
            decoder = decoder[ : terminator_delta ] + terminator + \
                      decoder[ terminator_delta + 4 : ]
        return decoder

#-----------------------------------------------------------------------------#

# Unit test.
def test():
    from ..base import CompilerState

    # A different implementation of XOR.
    def xor(bytes, key):
        return "".join([chr(ord(bytes[i])^ord(key[i%len(key)]))
                        for i in xrange(len(bytes))])

    # Test the 8-bit algorithm.
    bytes = "\x00" * 500
    key, terminator = NullFreeEncoder.find_key_8(bytes)
    assert "\x00" not in key
    assert "\x00" not in terminator
    encoded = NullFreeEncoder.encode_8(bytes, key, terminator)
    assert "\x00" not in encoded
    stub = NullFreeEncoder.get_decoder_8(key, terminator)
    assert "\x00" not in stub
    assert xor(encoded, key) == bytes + terminator
    shellcode = NullFreeEncoder(bytes)
    state = CompilerState()
    state.previous["pc"] = "esi"
    shellcode.compile(state)
    ##with open("nullfree.bin", "wb") as fd: fd.write(shellcode.bytes)
    ##with open("nullfree2.bin", "wb") as fd: fd.write(stub + encoded)
    key = shellcode.bytes[-2]
    terminator = chr( ord(shellcode.bytes[-1]) ^ ord(key) )
    encoded = NullFreeEncoder.encode_8(bytes, key, terminator)
    stub = NullFreeEncoder.get_decoder_8(key, terminator)
    assert shellcode.bytes == stub + encoded

    # Test the insertion of GetPC.
    shellcode = NullFreeEncoder(bytes)
    state = CompilerState()
    state.previous["pc"] = "esi"
    shellcode.compile(state)
    no_getpc = shellcode.bytes
    state = CompilerState()
    state.previous["pc"] = "eax"
    shellcode.compile(state)
    getpc_from_eax = shellcode.bytes
    shellcode.compile()
    getpc_normal = shellcode.bytes
    assert len(getpc_from_eax) == len(no_getpc) + 2
    assert len(getpc_normal) == len(no_getpc) + GetPC.length

    # Test the corner case for the 8-bit algorithm.
    bytes = "".join([chr(x) for x in xrange(256)])
    try:
        NullFreeEncoder.find_key_8(bytes)
        assert False
    except EncodingError:
        pass

    # Test the 32-bit alignment.
    assert NullFreeEncoder.align("hola manola!", 4) == "hola manola!"
    assert NullFreeEncoder.align("hola manola", 4) == "hola manola\x90"
    assert NullFreeEncoder.align("holamanola", 4) == "holamanola\x90\x90"
    assert NullFreeEncoder.align("holamanol", 4) == "holamanol\x90\x90\x90"

    # Test the 32-bit algorithm, short decoder stub.
    key = NullFreeEncoder.find_key(bytes, 4)
    assert "\x00" not in key
    terminator = NullFreeEncoder.find_terminator(bytes)
    assert "\x00\x00\x00\x00" not in bytes
    assert terminator == "\x00\x00\x00\x00"
    encoded = NullFreeEncoder.encode(bytes, key, terminator)
    assert "\x00" not in encoded
    assert encoded == NullFreeEncoder.align(encoded, 4)
    assert len(encoded) & 3
    stub, key_deltas, term_delta = NullFreeEncoder.get_decoder(key, terminator)
    assert "\x00" not in stub
    assert xor(encoded, key) == bytes + terminator
    shellcode = NullFreeEncoder(bytes)
    state = CompilerState()
    state.previous["pc"] = "esi"
    shellcode.compile(state)
    with open("nullfree3.bin", "wb") as fd: fd.write(shellcode.bytes)
    with open("nullfree4.bin", "wb") as fd: fd.write(stub + encoded)
    key = shellcode.bytes[-8:-4]
    terminator = struct.pack("<L",
                             struct.unpack("<L", shellcode.bytes[-4:])[0] ^
                             struct.unpack("<L", key)[0] )
    print shellcode.bytes[-8:].encode("hex")
    print key.encode("hex")
    print terminator.encode("hex")
    assert terminator == "\x00\x00\x00\x00"
    encoded = NullFreeEncoder.encode(bytes, key, terminator)
    stub = NullFreeEncoder.get_decoder(key, terminator)

    # Test the 32-bit algorithm, long decoder stub.
    bytes = bytes[:128] + "\x00\x00\x00\x00" + bytes[128:]
    key = NullFreeEncoder.find_key(bytes, 4)
    assert "\x00" not in key
    terminator = NullFreeEncoder.find_terminator(bytes)
    assert "\x00" not in terminator
    encoded = NullFreeEncoder.encode(bytes, key, terminator)
    assert "\x00" not in encoded
    assert encoded == NullFreeEncoder.align(encoded, 4)
    assert len(encoded) & 3
    stub, key_deltas, term_delta = NullFreeEncoder.get_decoder(key, terminator)
    assert "\x00" not in stub
    assert xor(encoded, key) == bytes + terminator
    shellcode = NullFreeEncoder(bytes)
    state = CompilerState()
    state.previous["pc"] = "esi"
    shellcode.compile(state)
    with open("nullfree5.bin", "wb") as fd: fd.write(shellcode.bytes)
    with open("nullfree6.bin", "wb") as fd: fd.write(stub + encoded)
    key = shellcode.bytes[-8:-4]
    terminator = struct.pack("<L",
                             struct.unpack("<L", shellcode.bytes[-4:])[0] ^
                             struct.unpack("<L", key)[0] )
    encoded = NullFreeEncoder.encode(bytes, key, terminator)
    stub = NullFreeEncoder.get_decoder(key, terminator)
