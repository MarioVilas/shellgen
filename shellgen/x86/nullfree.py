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
from ..base import Encoder, EncodingError, CompileError
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
        # TODO: we could predict if this will fail instead of trying.
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
        # TODO: Maybe there's a way to predict how long the key needs to be?
        except EncodingError:

            # Remember we failed with 8 bits so we don't try next time.
            self.__try_8_bit = False

            # For each possible key size, starting with one DWORD...
            key_size = 4
            while 1:
                try:

                    # Align the child shellcode size.
                    child_bytes = self.align(child_bytes, key_size)

                    # Calculate a XOR key and a terminator token.
                    key, terminator = self.find_key(child_bytes, key_size)

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

                            # Recalculate the XOR key and terminator token.
                            key, terminator = self.find_key(child_bytes,
                                                            key_size)

                            # Patch the decoder stub.
                            decoder = self.patch_decoder(decoder,
                                    key_deltas, key, term_delta, terminator)

                    # We've done it! Break out of the loop.
                    break

                # We failed, there's no valid key for this size.
                except EncodingError, e:

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
            raise AssertionError((
                "Internal error!\n"
                "  Class:   %s\n"
                "  Key:     %s\n"
                "  Token:   %s\n"
                "  Prefix:  %s\n"
                "  Decoder: %s\n"
                "  Payload: %s\n"
            ) % (
                self.__class__.__name__,
                key.encode("hex"),
                terminator.encode("hex"),
                prefix.encode("hex"),
                decoder.encode("hex"),
                child_bytes.encode("hex"),
            ))
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

    @classmethod
    def find_key(cls, bytes, key_size):
        """
        Find a suitable n-byte XOR key and terminator token
        for the given bytecode.

        @type  bytes: str
        @param bytes: Bytecode to encode.
            Must be at least C{key_size} bytes long.

        @type  key_size: int
        @param key_size: Size of the key, in bytes.

        @rtype:  tuple(str, str)
        @return: n-byte XOR key and terminator token, packed as two strings.

        @raise EncodingError: No valid key found for this size.
        """
        randint   = random.randint
        pack      = struct.pack
        unpack    = struct.unpack

        # Precalculate the range of possible keysize-relative positions.
        key_range = range(key_size)

        # Find the keysize-relative position of all characters,
        # except for the null character.
        position = tuple([set() for _ in key_range])
        for index in xrange(len(bytes)):
            char = bytes[index]
            if char != "\x00":
                position[index % key_size].add(char)
        for index in key_range:
            if not position[index]:
                raise EncodingError(
                    "No valid %d-byte XOR key could be found." % key_size)

        # If we're lucky, we may use four nulls as the terminator. This allows
        # an optimization in the decoder stub. If that fails, any use four
        # characters we already have in those positions.
        spliced = [ bytes[i:i+4] for i in xrange(0, len(bytes), 4) ]
        terminator = "\0\0\0\0"
        if terminator in spliced:
            if (len(position[0]) == 1 and
                len(position[1]) == 1 and
                len(position[2]) == 1 and
                len(position[3]) == 1):     # infinite loop!
                    raise EncodingError(
                        "No valid %d-byte XOR key could be found." % key_size)
            while True:
                terminator = (
                    list(position[0])[randint(0,len(position[0])-1)] +
                    list(position[1])[randint(0,len(position[1])-1)] +
                    list(position[2])[randint(0,len(position[2])-1)] +
                    list(position[3])[randint(0,len(position[3])-1)]
                )
                if terminator not in spliced:
                    break

        # For each keysize-relative position find the characters that are NOT
        # there, from those pick any character, and combine it into the key.
        # If there are no candidates for this position, then there's no valid
        # key for this size.
        key = ""
        good_chars = set( pack("B" * 255, *xrange(1, 256)) )
        for index in key_range:
            candidates = good_chars.difference( position[index] )
            if not candidates:
                raise EncodingError(
                    "No valid %d-byte XOR key could be found." % key_size)
            key += tuple(candidates)[ randint(0, len(candidates) - 1) ]

        # Return the key and terminator.
        return key, terminator

    @classmethod
    def get_decoder(cls, key, terminator):
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
        @raise CompileError: The decoder stub could not be compiled.
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
                var_size = ((len(key) >> 2) * 7)
                decoder = ["\x83\xC6" + pack("B", 7 + var_size) + "\x89\xF7"]
                key_deltas = []
                for i in xrange(0, len(key), 4):
                    key_deltas.append(7 + (i * 7))
                    decoder.append("\xAD\x35" + key[i:i+4] + "\xAB")
                decoder.append("\x75" + pack("b", -2 - var_size))
                return "".join(decoder), key_deltas, None

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
                var_size = (len(key) >> 2) * 7
                decoder = ["\x83\xC6" + pack("B", 12 + var_size) + "\x89\xF7"]
                key_deltas = []
                for i in xrange(0, len(key), 4):
                    key_deltas.append(7 + (i * 7))
                    decoder.append("\xAD\x35" + key[i:i+4] + "\xAB")
                decoder.append("\x3D" + terminator +
                               "\x75" + pack("b", -7 - var_size))
                return "".join(decoder), key_deltas, var_size + 6

        except struct.error:
            raise CompileError("The decoder stub could not be compiled.", cls)

    @classmethod
    def encode(cls, bytes, key, terminator):
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
        encoded = struct.pack(fmt, *bytes)
        if "\x00" in encoded:
            raise AssertionError((
                "Internal error!\n"
                "  Class  : %s\n"
                "  Key:     %s\n"
                "  Token:   %s\n"
                "  Encoded: %s\n"
            ) % (
                cls.__name__,
                struct.pack("B" * len(key), *key).encode("hex"),
                terminator.encode("hex"),
                " ".join([c.encode("hex") for c in encoded])
            ))
        return encoded

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

    # Test the insertion of GetPC when using the 8-bit algorithm.
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
    bytes = "".join([chr(x) for x in xrange(256)])
    key, terminator = NullFreeEncoder.find_key(bytes, 4)
    assert "\x00" not in key
    assert "\x00\x00\x00\x00" not in bytes
    assert terminator == "\x00\x00\x00\x00"
    encoded = NullFreeEncoder.encode(bytes, key, terminator)
    assert "\x00" not in encoded
    assert encoded == NullFreeEncoder.align(encoded, 4)
    assert (len(encoded) & 3) == 0
    stub, key_deltas, term_delta = NullFreeEncoder.get_decoder(key, terminator)
    assert term_delta is None
    assert "\x00" not in stub
    assert xor(encoded, key) == bytes + terminator
    shellcode = NullFreeEncoder(bytes)
    state = CompilerState()
    state.previous["pc"] = "esi"
    shellcode.compile(state)
    ##with open("nullfree3.bin", "wb") as fd: fd.write(shellcode.bytes)
    ##with open("nullfree4.bin", "wb") as fd: fd.write(stub + encoded)
    assert len(key_deltas) == 1
    key = shellcode.bytes[key_deltas[0]:key_deltas[0]+4]
    terminator = struct.pack("<L",
                             struct.unpack("<L", shellcode.bytes[-4:])[0] ^
                             struct.unpack("<L", key)[0] )
    assert terminator == "\x00\x00\x00\x00"
    encoded = NullFreeEncoder.encode(bytes, key, terminator)
    stub, key_deltas, term_delta = NullFreeEncoder.get_decoder(key, terminator)
    assert shellcode.bytes == stub + encoded

    # Test the 32-bit algorithm, long decoder stub.
    bytes = "".join([chr(x) for x in xrange(256)])
    bytes += "\x00\x00\x00\x00"
    key, terminator = NullFreeEncoder.find_key(bytes, 4)
    assert "\x00" not in key
    assert "\x00" not in terminator
    encoded = NullFreeEncoder.encode(bytes, key, terminator)
    assert "\x00" not in encoded
    assert encoded == NullFreeEncoder.align(encoded, 4)
    assert (len(encoded) & 3) == 0
    stub, key_deltas, term_delta = NullFreeEncoder.get_decoder(key, terminator)
    assert term_delta is not None
    assert "\x00" not in stub
    assert xor(encoded, key) == bytes + terminator
    shellcode = NullFreeEncoder(bytes)
    state = CompilerState()
    state.previous["pc"] = "esi"
    shellcode.compile(state)
    ##with open("nullfree5.bin", "wb") as fd: fd.write(shellcode.bytes)
    ##with open("nullfree6.bin", "wb") as fd: fd.write(stub + encoded)
    key = shellcode.bytes[-8:-4]
    terminator = struct.pack("<L",
                             struct.unpack("<L", shellcode.bytes[-4:])[0] ^
                             struct.unpack("<L", key)[0] )
    encoded = NullFreeEncoder.encode(bytes, key, terminator)
    stub, key_deltas, term_delta = NullFreeEncoder.get_decoder(key, terminator)
    assert shellcode.bytes == stub + encoded

    # Test the 32-bit algorithm for impossible cases.
    bytes = "".join(["\x00" + (chr(x) * 3) for x in xrange(256)])
    try:
        key, terminator = NullFreeEncoder.find_key(bytes, 4)
        assert False
    except EncodingError:
        pass
    bytes = "".join([chr(x) * 4 for x in xrange(256)])
    try:
        key, terminator = NullFreeEncoder.find_key(bytes, 4)
        assert False
    except EncodingError:
        pass

    # Test the insertion of GetPC with the 32-bit algorithm, short decoder.
    bytes = "".join([chr(x) for x in xrange(256)])
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

    # Test the insertion of GetPC with the 32-bit algorithm, long decoder.
    bytes = "".join([chr(x) for x in xrange(256)])
    bytes += "\x00\x00\x00\x00"
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

    # Test the 32-bit algorithm for longer keys.
    bytes = "".join([(chr(x) * 64) for x in xrange(256)])
    shellcode = NullFreeEncoder(bytes)
    assert "\x00" not in shellcode.bytes
    assert len(shellcode.bytes) > (len(bytes) + 4)
    with open("nullfree7.bin", "wb") as fd: fd.write(shellcode.bytes)

    # Test a corner case that can't be encoded by this algorithm.
    # The decoder stub gets too large and fails to compile.
    # XXX: This could be fixed but I don't see the point right now.
    try:
        bytes = "".join([(chr(x) * 128) for x in xrange(256)])
        shellcode = NullFreeEncoder(bytes)
        shellcode.bytes
        assert False
    except CompileError:
        pass
