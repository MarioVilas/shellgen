#!/usr/bin/env python

###############################################################################
## Shellcode export formats for ShellGen                                     ##
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

"""
Shellcode export formats for ShellGen
"""

from __future__ import absolute_import

__all__ = [
    "as_python_source",
]

#-----------------------------------------------------------------------------#

def export(fn):
    """
    Decorator function for shellcode exporters.

    It validates the arguments and converts the output filename
    into an open file object which is ensured to be closed before
    returning.
    """
    def _export(shellcode, output):
        if not hasattr(shellcode, "bytes"):
            raise TypeError(
                "Expected Shellcode, got %s instead" % type(shellcode))
        if not hasattr(output, "write"):
            with open(output, "wb") as output:
                return fn(shellcode, output)
        return fn(shellcode, output)

#-----------------------------------------------------------------------------#

@export
def as_raw_binary(shellcode, output):
    """
    Export the given shellcode as a raw binary file.

    @note: This function will not generate executable files.
        The bytecode is just dumped into the file without format.

    @type  shellcode: L{Shellcode}
    @param shellcode: Any shellcode.

    @type  output: file or str
    @param output: Filename or open file object.

    @rtype:  int
    @return: Number of bytes written.
    """
    raise NotImplementedError("This export format is not implemented yet.")

@export
def as_hexadecimal(shellcode, output):
    """
    Export the given shellcode as an hexadecimal string.
    Useful for debugging or searching for the bytecode with an hex editor.

    @type  shellcode: L{Shellcode}
    @param shellcode: Any shellcode.

    @type  output: file or str
    @param output: Filename or open file object.

    @rtype:  int
    @return: Number of bytes written.
    """
    raise NotImplementedError("This export format is not implemented yet.")

@export
def as_python_source(shellcode, output):
    """
    Export the given shellcode as Python source code
    to be embedded into your exploit.

    @type  shellcode: L{Shellcode}
    @param shellcode: Any shellcode.

    @type  output: file or str
    @param output: Filename or open file object.

    @rtype:  int
    @return: Number of bytes written.
    """
    raise NotImplementedError("This export format is not implemented yet.")

@export
def as_ruby_source(shellcode, output):
    """
    Export the given shellcode as Ruby source code
    to be embedded into your exploit.

    @type  shellcode: L{Shellcode}
    @param shellcode: Any shellcode.

    @type  output: file or str
    @param output: Filename or open file object.

    @rtype:  int
    @return: Number of bytes written.
    """
    raise NotImplementedError("This export format is not implemented yet.")

@export
def as_perl_source(shellcode, output):
    """
    Export the given shellcode as Perl source code
    to be embedded into your exploit.

    @type  shellcode: L{Shellcode}
    @param shellcode: Any shellcode.

    @type  output: file or str
    @param output: Filename or open file object.

    @rtype:  int
    @return: Number of bytes written.
    """
    raise NotImplementedError("This export format is not implemented yet.")

@export
def as_php_source(shellcode, output):
    """
    Export the given shellcode as PHP source code
    to be embedded into your exploit.

    @type  shellcode: L{Shellcode}
    @param shellcode: Any shellcode.

    @type  output: file or str
    @param output: Filename or open file object.

    @rtype:  int
    @return: Number of bytes written.
    """
    raise NotImplementedError("This export format is not implemented yet.")

@export
def as_c_source(shellcode, output):
    """
    Export the given shellcode as C source code
    to be embedded into your exploit.

    @type  shellcode: L{Shellcode}
    @param shellcode: Any shellcode.

    @type  output: file or str
    @param output: Filename or open file object.

    @rtype:  int
    @return: Number of bytes written.
    """
    raise NotImplementedError("This export format is not implemented yet.")
