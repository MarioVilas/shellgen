#!/usr/bin/env python

###############################################################################
## Prepackaged payloads for ShellGen                                         ##
###############################################################################

# Copyright (c) 2012-2015 Mario Vilas
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

"""
Prepackaged payloads for ShellGen.

@group Actions:
    shell, download_exec, execute, adduser, chmod

@group Encoders:
    nullfree_encode, xor_encode, ascii_encode, alpha_encode, unicode_encode
"""

from __future__ import absolute_import
from .util import get_shellcode_class

__all__ = [

    # Actions.
    'shell',
    'download_exec',
    'execute',
    'adduser',
    'chmod',

    # Encoders.
    'nullfree_encode',
    'xor_encode',
    'ascii_encode',
    'alpha_encode',
    'unicode_encode',

    # Stagers.
    # TODO
]

# NOTE: all methods here must invoke the compile() method before returning the
# shellcode object, so if there are any errors they show up immediately.

###############################################################################
## Actions.

def shell(arch, os, **options):
    """
    Spawn a remote shell using the specified communication channel.

    Typically used for B{network service} exploits.

    @type  arch: str
    @param arch: Target processor architecture.

    @type  os: str
    @param os: Target operating system.

    @type    connect: str
    @keyword connect: Communication channel.
        Must be one of the following:
         - C{bind_tcp}: Listen on the given TCP port for incoming connections.
         - C{reverse_tcp}: Connect back to the given TCP port on this machine.
         - C{reuse_tcp}: Reuse an existing TCP socket (for network services).
         - C{none}: Do not use a communication channel (for inetd programs).
           Defaults to C{bind_tcp}.

    @type    address: str
    @keyword address: IP address to bind to (C{bind_tcp}) or connect to
        (C{reverse_tcp}, C{reuse_tcp}). For C{bind_tcp} the default is
        C{"0.0.0.0"}. Unused for C{none}.

    @type    port: int
    @keyword port: TCP port for the communication channel (C{bind_tcp},
        C{reverse_tcp}). Unused for C{reuse_tcp} and C{none}.

    @type    staged: bool
    @keyword staged: C{True} to split execution into two stages, C{False}
        otherwise. The first stage uses the communication channel to download
        the second stage, thus reducing the payload size. Some platforms may
        not support this option. Defaults to C{False}.

    @rtype:  L{Shellcode}
    @return: Shellcode object with the requested payload.

    @raise TypeError: A required option is missing, or an option contains the
        wrong data type.

    @raise ValueError: An option contains the correct data type but an
        incorrect value.

    @raise NotImplementedError: The specified payload does not support the
        requested architecture, operating system or specified options.
    """
    raise NotImplementedError()

def download_exec(arch, os, url, **options):
    """
    Download an executable file and run it.

    Typically used for B{browser} or B{file} exploits.

    @type  arch: str
    @param arch: Target processor architecture.

    @type  os: str
    @param os: Target operating system.

    @type    url: str
    @keyword url: URL of the executable file to download and execute.
        Different platforms may support different URL schemas.

    @type    pathname: str
    @keyword pathname: Local pathname for the executable. Some platforms may
        not support this option.

    @rtype:  L{Shellcode}
    @return: Shellcode object with the requested payload.

    @raise TypeError: A required option is missing, or an option contains the
        wrong data type.

    @raise ValueError: An option contains the correct data type but an
        incorrect value.

    @raise NotImplementedError: The specified payload does not support the
        requested architecture, operating system or specified options.
    """
    raise NotImplementedError()

def execute(arch, os, command, **options):
    """
    Execute an arbitrary shell command and quit.

    Typically used for B{privilege escalation} exploits.

    @type  arch: str
    @param arch: Target processor architecture.

    @type  os: str
    @param os: Target operating system.

    @type    command: str
    @keyword command: System command to execute. May be any shell command or
        any executable file, followed by its arguments (if any).

    @rtype:  L{Shellcode}
    @return: Shellcode object with the requested payload.

    @raise TypeError: A required option is missing, or an option contains the
        wrong data type.

    @raise ValueError: An option contains the correct data type but an
        incorrect value.

    @raise NotImplementedError: The specified payload does not support the
        requested architecture, operating system or specified options.
    """
    raise NotImplementedError()

# TODO think of smarter defaults for this one!
def adduser(arch, os, **options):
    """
    Add a new privileged user to the system and quit.

    Typically used for B{privilege escalation} exploits.

    @type  arch: str
    @param arch: Target processor architecture.

    @type  os: str
    @param os: Target operating system.

    @type    username: str
    @keyword username: Username to add. Defaults to C{"newuser"}.

    @type    password: str
    @keyword password: Password to the new user. Defaults to C{"1234"}.
        Use an empty string for no password.

    @rtype:  L{Shellcode}
    @return: Shellcode object with the requested payload.

    @raise TypeError: A required option is missing, or an option contains the
        wrong data type.

    @raise ValueError: An option contains the correct data type but an
        incorrect value.

    @raise NotImplementedError: The specified payload does not support the
        requested architecture, operating system or specified options.
    """
    raise NotImplementedError()

def chmod(arch, os, **options):
    """
    Change the permissions of the given file and quit.

    Typically used for B{privilege escalation} exploits.

    @note: This payload is not supported on Windows.

    @type  arch: str
    @param arch: Target processor architecture.

    @type  os: str
    @param os: Target operating system.

    @type    pathname: str
    @keyword pathname: Pathname of the file to modify.
        Defaults to C{"/usr/bin/python"}.

    @type    mode: int
    @keyword mode: Octal mode for the file. Defaults to C{6777}.

    @rtype:  L{Shellcode}
    @return: Shellcode object with the requested payload.

    @raise TypeError: A required option is missing, or an option contains the
        wrong data type.

    @raise ValueError: An option contains the correct data type but an
        incorrect value.

    @raise NotImplementedError: The specified payload does not support the
        requested architecture, operating system or specified options.
    """
    raise NotImplementedError()

###############################################################################
## Encoders.

def nullfree_encode(payload):
    """
    Encode the payload and prepend a decoder to bypass null character
    restrictions.

    @type  payload: L{Shellcode}
    @param payload: Payload to encode.

    @rtype:  L{Shellcode}
    @return: Shellcode object with the encoded payload.

    @raise ArithmeticError: Could not satisfy the null character constraint.

    @raise TypeError: A required option is missing, or an option contains the
        wrong data type.

    @raise ValueError: An option contains the correct data type but an
        incorrect value.

    @raise NotImplementedError: The specified encoder does not support the
        requested architecture, operating system or specified options.
    """
    try:
        encoder = get_shellcode_class(payload.arch, payload.os, "nullfree", "NullFreeEncoder")
    except NotImplementedError:
        encoder = get_shellcode_class(payload.arch, "nullfree", "NullFreeEncoder")
    payload = encoder(payload)
    payload.compile()
    return payload

def xor_encode(payload, bad_chars = "\0\r\n\x1a\"'`%,;:."):
    """
    Encode the payload and prepend a XOR-based decoder to bypass character
    filters.

    @type  payload: L{Shellcode}
    @param payload: Payload to encode.

    @type    bad_chars: str
    @keyword bad_chars:
        String containing all the characters that must be avoided.
        Defaults to the following characters:
        C{00 0A 0D 1A 22 25 27 2C 2E 3A 3B 60}

    @rtype:  L{Shellcode}
    @return: Shellcode object with the encoded payload.

    @raise ArithmeticError: Could not satisfy the character constraints, or
        the decoder itself couldn't avoid using bad characters.

    @raise TypeError: A required option is missing, or an option contains the
        wrong data type.

    @raise ValueError: An option contains the correct data type but an
        incorrect value.

    @raise NotImplementedError: The specified encoder does not support the
        requested architecture, operating system or specified options.
    """
    raise NotImplementedError()

def ascii_encode(payload, allow_upper = True,
                          allow_lower = True):
    """
    Encode the payload and prepend a decoder so the payload
    uses only standard ASCII (7-bit) characters.

    @type  payload: L{Shellcode}
    @param payload: Payload to encode.

    @type  allow_upper: bool
    @param allow_upper: C{True} if uppercase letters are allowed, C{False}
        otherwise. Defaults to C{True}.

    @type  allow_lower: bool
    @param allow_lower: C{True} if uppercase letters are allowed, C{False}
        otherwise. Defaults to C{True}.

    @rtype:  L{Shellcode}
    @return: Shellcode object with the encoded payload.

    @raise ArithmeticError: Could not satisfy the character constraints.

    @raise TypeError: A required option is missing, or an option contains the
        wrong data type.

    @raise ValueError: An option contains the correct data type but an
        incorrect value.

    @raise NotImplementedError: The specified encoder does not support the
        requested architecture, operating system or specified options.
    """
    raise NotImplementedError()

def alpha_encode(payload, allow_upper = True,
                          allow_lower = True):
    """
    Encode the payload and prepend a decoder so the payload
    uses only alphanumeric characters.

    @type  payload: L{Shellcode}
    @param payload: Payload to encode.

    @type  allow_upper: bool
    @param allow_upper: C{True} if uppercase letters are allowed, C{False}
        otherwise. Defaults to C{True}.

    @type  allow_lower: bool
    @param allow_lower: C{True} if uppercase letters are allowed, C{False}
        otherwise. Defaults to C{True}.

    @rtype:  L{Shellcode}
    @return: Shellcode object with the encoded payload.

    @raise ArithmeticError: Could not satisfy the character constraints.

    @raise TypeError: A required option is missing, or an option contains the
        wrong data type.

    @raise ValueError: An option contains the correct data type but an
        incorrect value.

    @raise NotImplementedError: The specified encoder does not support the
        requested architecture, operating system or specified options.
    """
    raise NotImplementedError()

def unicode_encode(payload, allow_upper = True,
                            allow_lower = True,
                            allow_null  = False):
    """
    Encode the payload and prepend a decoder so the payload
    can survive ANSI to WIDECHAR conversion.

    @type  payload: L{Shellcode}
    @param payload: Payload to encode.

    @type  allow_upper: bool
    @param allow_upper: C{True} if uppercase letters are allowed, C{False}
        otherwise. Defaults to C{True}.

    @type  allow_lower: bool
    @param allow_lower: C{True} if uppercase letters are allowed, C{False}
        otherwise. Defaults to C{True}.

    @type  allow_null: bool
    @param allow_null: C{True} if null wchars are allowed, C{False} otherwise.
        Defaults to C{False}.

    @rtype:  L{Shellcode}
    @return: Shellcode object with the encoded payload.

    @raise ArithmeticError: Could not satisfy the character constraints.

    @raise TypeError: A required option is missing, or an option contains the
        wrong data type.

    @raise ValueError: An option contains the correct data type but an
        incorrect value.

    @raise NotImplementedError: The specified encoder does not support the
        requested architecture, operating system or specified options.
    """
    raise NotImplementedError()

###############################################################################
## Unit test.

def test():
    "Unit test."

    # TODO
    pass
