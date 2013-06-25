#!/usr/bin/env python

###############################################################################
## ShellGen - Shellcode generator library                                    ##
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
ShellGen - Shellcode generator library
======================================

Use cases
---------

ShellGen has four basic use cases:
 - Generate a canned payload and export it as source code in your favorite
   programming language. Then copy and paste the source code into your exploit.

   This is the easiest way. :)

 - Import ShellGen from your Python exploit and generate a canned payload on
   the fly.

   This allows you to parameterize your exploit payload,
   instead of hardcoding it.

 - Import ShellGen from your Python exploit and use the individual shellcodes
   to build a custom payload.

   This allows even more flexibility, as you can change what your payload does
   at a greater level of detail.

 - Import ShellGen from your Python exploit and write your own shellcodes.
   You can do this by inheriting from one of the ShellGen classes within your
   exploit code, or by adding a new C{.py} file to ShellGen itself.

   If you want to share your custom shellcode to be added to ShellGen, just
   drop us an email or find us on Twitter! We're more than happy to receive
   constributions. :)

Module structure
----------------

The most important modules are:
 - L{shellgen.payload}: This is a simple interface to get just the canned
   payloads from ShellGen. Most users will just want this.
 - L{shellgen.base}: This is where the base classes for all shellcodes are.
   See this to learn how ShellGen works on the inside.
 - L{shellgen.export}: This is for exporting shellcodes to source code files.
 - L{shellgen.util}: Miscellaneous utility functions. Check them out so you
   don't end up reinventing the wheel!

The rest of the modules contain the shellcodes themselves, organized by target
platform: C{shellgen.B{<processor architecture>}.B{<operating system>}.B{<module>}}.

You'll notice module names and class names are repeated throughout ShellGen.
This is intentional - by providing a consistent interface to similar shellcodes
of different platforms, the L{shellgen.payload} module can (almost) seamlessly
build canned payloads for any supported platform without much platform-specific
logic in it. It also makes it easier to remember the shellcode names when
customizing your exploit's payload.

The C{abstract} architecture contains platform-independent functionality used
by other shellcodes, to avoid code repetition. Sometimes, shellcodes may import
each other to reuse some functionality (for example, most C{x86_64} shellcodes
just subclass their C{x86} counterparts and make the appropriate changes).

Extending ShellGen
------------------

To add your own shellcodes to the library, just drop your C{.py} file in the
corresponding place of the directory structure. If the target platform is
missing, simply create a new directory and add an empty C{__init__.py} in it so
Python recognizes it.

You may also define your custom shellcodes inside your exploit, but then you'll
have to explicitly tell ShellGen which platforms they support by defining the
L{Shellcode.arch} and L{Shellcode.os} properties in your classes.

Reference documentation
-----------------------

@type version: float
@var  version: Library version.
"""

from __future__ import absolute_import
from .base import *

__all__ = [
    "version",
    "ShellcodeWarning",
    "CompilerState",
    "Shellcode", "Dynamic", "Static", "Raw",
    "Container", "Concatenator", "Decorator", "Encoder", "Stager",
]

version = 0.1
