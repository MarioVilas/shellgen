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
Shellcode export formats for ShellGen.

@type exporters: dict(str -> callable)
@var  exporters:
    Map of output formats to their corresponding exporter functions.
    If you add your own format here, L{export}() will use it.
"""

from __future__ import absolute_import

import struct

__all__ = [

    # Generic entrypoint.
    "export",
    "exporter",
    "exporters",

    # Exporter functions.
    "as_raw_binary",
    "as_hexadecimal",
    "as_python_source",
    "as_ruby_source",
    "as_perl_source",
    "as_php_source",
    "as_c_source",
]

#-----------------------------------------------------------------------------#

def exporter(fn):
    """
    Decorator function for shellcode exporters.

    It validates the arguments and converts the output filename
    into an open file object which is ensured to be closed before
    returning.
    """
    def _exporter(shellcode, output):
        if not hasattr(shellcode, "bytes"):
            raise TypeError(
                "Expected Shellcode, got %s instead" % type(shellcode))
        if not hasattr(output, "write"):
            with open(output, "wb") as output:
                return fn(shellcode, output)
        return fn(shellcode, output)

#-----------------------------------------------------------------------------#

# Internal function to export to source in most programming languages.
def _generic_source_exporter(shellcode, output, prologue, epilogue,
                             char_fmt = "\\x%.2x",
                             line_fmt = "    \"%s\"\n",
                             last_fmt = None):
    bytes = shellcode.bytes
    chars = struct.unpack("B" * len(bytes), bytes)
    try:
        prologue %= len(bytes)
    except Exception:
        pass
    output.write(prologue)
    size = len(prologue)
    last_index = len(chars) & (~15)
    if not last_fmt:
        last_fmt = line_fmt
    for index in xrange(0, len(chars), 16):
        line = "".join( char_fmt % c for c in chars[ index : index + 16 ] )
        if index < last_index:
            line = line_fmt % line
        else:
            line = last_fmt % line
        output.write(line)
        size += len(line)
    output.write(epilogue)
    size += len(epilogue)
    return size

#-----------------------------------------------------------------------------#
# All export functions have the exact same interface.

@exporter
def as_raw_binary(shellcode, output):
    """
    Export the given shellcode as a raw binary file.

    @note: This function will not generate executable files.
        The bytecode is just dumped into the file without format.

    @warn: The file B{MUST} be opened in B{binary} mode.
        Failure to do so may result in data corruption!

    @type  shellcode: L{Shellcode}
    @param shellcode: Any shellcode.

    @type  output: file or str
    @param output: Filename or open file object.

    @rtype:  int
    @return: Number of bytes written.
    """
    bytes = shellcode.bytes
    output.write(bytes)
    return len(bytes)

@exporter
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
        May be inaccurate if the file was not opened in binary mode on certain
        platforms. For example on Windows an extra C{\r} will be prepended to
        each C{\n} character by Python without this function knowing about it.
    """
    bytes = shellcode.bytes
    chars = struct.unpack("B" * len(bytes), bytes)
    hexa  = " ".join("%.2X" % c for c in chars) + "\n"
    output.write(hexa)
    return len(hexa)

@exporter
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
        May be inaccurate if the file was not opened in binary mode on certain
        platforms. For example on Windows an extra C{\r} will be prepended to
        each C{\n} character by Python without this function knowing about it.
    """
    return _generic_source_exporter(
        shellcode, output,
        prologue = "# %d bytes\nshellcode = (\n",
        epilogue = ")\n",
    )

@exporter
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
        May be inaccurate if the file was not opened in binary mode on certain
        platforms. For example on Windows an extra C{\r} will be prepended to
        each C{\n} character by Python without this function knowing about it.
    """
    return _generic_source_exporter(
        shellcode, output,
        prologue = "# %d bytes\nshellcode = \\\n",
        line_fmt = "    \"%s\"\\\n",
        last_fmt = "    \"%s\"\n",
        epilogue = "",
    )

@exporter
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
        May be inaccurate if the file was not opened in binary mode on certain
        platforms. For example on Windows an extra C{\r} will be prepended to
        each C{\n} character by Python without this function knowing about it.
    """
    return _generic_source_exporter(
        shellcode, output,
        prologue = "# %d bytes\nmy $shellcode =\n",
        line_fmt = "\"%s\" .\n",
        last_fmt = "\"%s\";\n",
        epilogue = "",
    )

@exporter
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
        May be inaccurate if the file was not opened in binary mode on certain
        platforms. For example on Windows an extra C{\r} will be prepended to
        each C{\n} character by Python without this function knowing about it.
    """
    return _generic_source_exporter(
        shellcode, output,
        prologue = "# %d bytes\n$shellcode = ''\n",
        line_fmt = "           . '%s'\n",
        last_fmt = "           . '%s';\n",
        epilogue = "$js_shellcode = 'var shellcode=unescape(\"' . urlencode($shellcode) . '\");';\n",
    )

@exporter
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
        May be inaccurate if the file was not opened in binary mode on certain
        platforms. For example on Windows an extra C{\r} will be prepended to
        each C{\n} character by Python without this function knowing about it.
    """
    return _generic_source_exporter(
        shellcode, output,
        prologue = "// %d bytes\nchar shellcode[] = {\n",
        epilogue = "};\n",
    )

#-----------------------------------------------------------------------------#

# Map of output formats to their corresponding exporter functions.
exporters = {
    "raw":    as_raw_binary,
    "hex":    as_hexadecimal,
    "python": as_python_source,
    "ruby":   as_ruby_source,
    "perl":   as_perl_source,
    "php":    as_php_source,
    "c":      as_c_source,
}

# Parameterized exporter functions entry point.
def export(shellcode, output, format = "python"):
    """
    Export the given shellcode with the desired format.

    @note: Generally you'll want to use this function only when the output
        format comes from user input. In your own scripts you can just call
        the corresponding exporter function from this module.

    @warn: For binary output formats, the output file B{MUST} be opened in
        B{binary} mode. Failure to do so may result in data corruption!

    @type  shellcode: L{Shellcode}
    @param shellcode: Any shellcode.

    @type  output: file or str
    @param output: Filename or open file object.

    @type  format: str
    @param format: Desired output format.
        Must be one of the following:
         - C{"raw"}: Raw binary file with no format.
         - C{"hex"}: Hexadecimal string.
         - C{"python"}: Python source code.
         - C{"ruby"}: Ruby source code.
         - C{"perl"}: Perl source code.
         - C{"php"}: PHP source code.
         - C{"c"}: C source code.

    @rtype:  int
    @return: Number of bytes written.
        May be inaccurate if the file was not opened in binary mode on certain
        platforms. For example on Windows an extra C{\r} will be prepended to
        each C{\n} character by Python without this function knowing about it.
    """
    try:
        function = exporters[ format.strip().lower() ]
    except KeyError:
        raise ValueError("Unknown output format: %r" % format)
    return function(shellcode, output)
