#!/usr/bin/env python

###############################################################################
## ShellGen - Shellcode generator library                                    ##
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
   exploit code, or by adding a new *.py* file to ShellGen itself.

   If you want to share your custom shellcode to be added to ShellGen, just
   drop us an email or find us on Twitter! We're more than happy to receive
   constributions. :)

Module structure
----------------

The most important modules are:
 - `shellgen.payload`: This is a simple interface to get just the canned
   payloads from ShellGen. Most users will just want this.
 - `shellgen.base`: This is where the base classes for all shellcodes are.
   See this to learn how ShellGen works on the inside.
 - `shellgen.export`: This is for exporting shellcodes to source code files.
 - `shellgen.util`: Miscellaneous utility functions. Check them out so you
   don't end up reinventing the wheel!

The rest of the modules contain the shellcodes themselves, organized by target
platform: shellgen.**[processor architecture]**.**[operating system]**.**[module]**.

You'll notice module names and class names are repeated throughout ShellGen.
This is intentional - by providing a consistent interface to similar shellcodes
of different platforms, the `shellgen.payload` module can (almost) seamlessly
build canned payloads for any supported platform without much platform-specific
logic in it. It also makes it easier to remember the shellcode names when
customizing your exploit's payload.

The *abstract* architecture contains platform-independent functionality used
by other shellcodes, to avoid code repetition. Sometimes, shellcodes may import
each other to reuse some functionality (for example, most *x86_64* shellcodes
just subclass their *x86* counterparts and make the appropriate changes).

Extending ShellGen
------------------

To add your own shellcodes to the library, just drop your *.py* file in the
corresponding place of the directory structure. If the target platform is
missing, simply create a new directory and add an empty *__init__.py* in it so
Python recognizes it.

You may also define your custom shellcodes inside your exploit, but then you'll
have to explicitly tell ShellGen which platforms they support by defining the
`Shellcode.arch` and `Shellcode.os` properties in your classes.

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
