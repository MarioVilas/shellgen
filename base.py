#!/usr/bin/env python

###############################################################################
# ShellGen - Shellcode generator library for Python                           #
###############################################################################

# Copyright (c) 2012 Mario Vilas
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

__all__ = [

    # Library version.
    "version",

    # Warnings issued by this library are always of this type.
    "ShellcodeWarning",

    # Base shellcode type.
    "Shellcode",

    # Dynamic shellcode, may change when compiled.
    "Dynamic",

    # Static shellcode, doesn't ever change.
    "Static",

    # Static shellcode built from raw bytes provided by the user.
    "Raw",

    # Container for other shellcodes.
    "Container",

    # Simple concatenation of shellcodes.
    "Concatenator",

    # Wraps around another shellcode to modify it.
    "Decorator",

    # Encodes another shellcode to avoid certain characters.
    "Encoder",

    # Splits the shellcode into multiple load stages.
    "Stager"
]

version = "0.1"

import weakref
import warnings

# Metaclass to make sure a given class cannot be subclassed.
class final(type):
    def __init__(cls, name, bases, namespace):
        super(final, cls).__init__(name, bases, namespace)
        for clazz in bases:
            if isinstance(clazz, final):
                raise TypeError("Class %s is final!" % clazz.__name__)

class ShellcodeWarning (Warning):
    pass

class Shellcode (object):

    # Should be redefined by subclasses.
    # TO DO: maybe define lists of possible values outside this class?
    arch      = None
    os        = None
    requires  = ()
    provides  = ()
    qualities = ()

    # Updated externally on object instances only by Containers.
    _parent = None

    @property
    def parent(self):
        if self._parent is not None:
            return self._parent()

    @property
    def bytes(self):
        raise NotImplementedError("Shellcodes MUST define \"bytes\"!")

    @property
    def stages(self):
        raise NotImplementedError("Stagers MUST define \"stages\"!")

    # Only Containers may have children.
    @property
    def children(self):
        return []

    # Default implementation causes the code to be compiled.
    # Subclasses may override this to return a constant when feasable.
    @property
    def length(self):
        return len(self.bytes)

    def compile(self):
        raise NotImplementedError("Subclasses MUST implement this method!")

    def clean(self):
        pass

    def __add__(self, other):
        if isinstance(other, str):    # bytes
            other = Raw(other, self.arch, self.os)
        elif not isinstance(other, Shellcode):
            return NotImplemented
        else:
            if self.arch and other.arch and self.arch != other.arch:
                msg = "Processor architectures don't match: %s and %s"
                msg = msg % (self.arch, other.arch)
                warnings.warn(msg, ShellcodeWarning)
            if self.os and other.os and self.os != other.os:
                msg = "Operating systems don't match: %s and %s"
                msg = msg % (self.os, other.os)
                warnings.warn(msg, ShellcodeWarning)
        return Concatenator(self, other)

    def __radd__(self, other):
        if isinstance(other, str):    # bytes
            other = Raw(other, self.arch, self.os)
        elif not isinstance(other, Shellcode):
            return NotImplemented
        else:
            if self.arch and other.arch and self.arch != other.arch:
                msg = "Processor architectures don't match: %s and %s"
                msg = msg % (self.arch, other.arch)
                warnings.warn(msg, ShellcodeWarning)
            if self.os and other.os and self.os != other.os:
                msg = "Operating systems don't match: %s and %s"
                msg = msg % (self.os, other.os)
                warnings.warn(msg, ShellcodeWarning)
        return Concatenator(other, self)

class Static (Shellcode):

    # Subclasses MUST define "bytes".

    # Only Stagers may have stages. Don't override this method elsewhere.
    @property
    def stages(self):
        return []

    def compile(self):
        pass

class Raw (Static):

    # Don't subclass this class.
    __metaclass__= final

    def __init__(self, bytes, arch, os,
                 requires = None, provides = None, qualities = None):
        super(Raw, self).__init__()
        self.bytes = bytes
        self.arch  = arch
        self.os    = os
        if requires:
            self.requires = requires
        if provides:
            self.provides = provides
        if qualities:
            self.qualities = qualities

class Dynamic (Shellcode):

    # Must be updated on object instances by the compile() method.
    _bytes = None

    @property
    def bytes(self):

        # Returns previously cached compilation if available.
        if self._bytes is not None:
            return self._bytes

        # Compile the shellcode. Clear the cache on error.
        try:
            self.compile()
        except:
            self.clean()
            raise

        # If compilation was successful but no bytes were produced,
        # set the cache as an empty string to prevent further calls.
        if self._bytes is None:
            self._bytes = ""

        # Return the compiled bytes.
        return self._bytes

    # Only Stagers may have stages. Don't override this method elsewhere.
    @property
    def stages(self):
        return []

    def clean(self):
        self._bytes = None

class Container (Dynamic):

    # Must be updated on object instances.
    _bytes    = None
    _stages   = None

    # Wraps on the compile() method to catch compilation errors.
    def __compile(self):

        # Compile the shellcode. Clear the cache on error.
        try:
            self.compile()
        except:
            self.clean()
            raise

        # If compilation was successful but no bytes were produced,
        # set the cache as an empty string to prevent further calls
        # from the "bytes" property method.
        if self._bytes is None:
            self._bytes  = ""

        # If compilation was successful but no stages were compiled,
        # set the cache as an empty list to prevent further calls
        # from the "stages" property method.
        if self._stages is None:
            self._stages = []

    def clean(self):
        self._bytes  = None
        self._stages = None

    @property
    def bytes(self):

        # Returns previously cached compilation if available.
        if self._bytes is not None:
            return self._bytes

        # Compile and return the bytes.
        self.__compile()
        return self._bytes

    # Containers inherit the stages of its children.
    # Don't override this method elsewhere.
    @property
    def stages(self):

        # Returns previously cached compiled stages if available.
        if self._stages is not None:
            return self._stages

        # Compile and return the compiled stages.
        self.__compile()
        return self._stages

    @property
    def children(self):
        raise NotImplementedError("Containers MUST define \"children\"!")

    # Helper method that compiles all children and their stages.
    def compile_children(self):
        bytes  = ""
        stages = []
        for child in self._children:
            child.compile()
            bytes += child.bytes
            stages.extend(child.stages)
        return bytes, stages

class Concatenator (Container):

    # Don't subclass this class.
    __metaclass__= final

    def __init__(self, *children):
        super(Container, self).__init__()
        self._children = list(children)
        for child in self._children:
            if not isinstance(child, Shellcode):
                raise TypeError(
                    "Expected Shellcode, got %s instead" % type(child))
            if child.parent:
                raise ValueError("Already had a parent: %r" % child.parent)
        parent = weakref.ref(self)
        for child in self._children:
            child._parent = parent

    def __iadd__(self, other):
        if isinstance(other, str):    # bytes
            other = Raw(other, self.arch, self.os)
        elif not isinstance(other, Shellcode):
            return NotImplemented
        else:
            if self.arch and other.arch and self.arch != other.arch:
                msg = "Processor architectures don't match: %s and %s"
                msg = msg % (self.arch, other.arch)
                warnings.warn(msg, ShellcodeWarning)
            if self.os and other.os and self.os != other.os:
                msg = "Operating systems don't match: %s and %s"
                msg = msg % (self.os, other.os)
                warnings.warn(msg, ShellcodeWarning)
            if isinstance(other, Concatenator):
                self._children.extend(other.children)
                parent = weakref.ref(self)
                for child in other.children:
                    oldparent = child.parent
                    if oldparent and oldparent != other:
                        msg = "Already had a parent: %r" % oldparent
                        warnings.warn(msg, ShellcodeWarning)
                    child._parent = parent
                return self
        self._children.append(other)
        return self

    @property
    def children(self):
        return self._children

    # Concatenate all bytes and gather all stages.
    def compile(self):
        self._bytes, self._stages = self.compile_children()

class Decorator (Container):

    # Must be updated on object instances by the constructor.
    _child = None

    # Container with only one child, that modifies its compilation.
    def __init__(self, child):
        self._child = child

    @property
    def children(self):
        if self._child is None:
            return []
        return [self._child]

    # Must set both self._bytes and self._stages.
    def compile(self):
        raise NotImplementedError(
            "Decorators MUST implement the compile() method!")

class Encoder (Decorator):

    # Must set both self._bytes and self._stages.
    def compile(self):
        raise NotImplementedError(
            "Encoders MUST implement the compile() method!")

class Stager (Decorator):

    # Must set both self._bytes and self._stages.
    # Remember to check for inherited stages!
    def compile(self):
        raise NotImplementedError(
            "Stagers MUST implement the compile() method!")
