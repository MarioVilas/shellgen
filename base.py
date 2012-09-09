#!/usr/bin/env python

###############################################################################
## ShellGen - Shellcode generator library for Python                         ##
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

    # Helper function to resolve shellcode classes dynamically.
    "get_shellcode_class",

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

# Autodetects the platform from the package name if it's ours.
# User-defined shellcodes should set "arch" and "os" instead.
try:
    base_package, base_file = __name__.split(".")[-2:]
except Exception:
    raise ImportError("Trying to load %s outside of its package" % __file__)
class meta_shellcode(type):
    def __init__(cls, name, bases, namespace):
        super(meta_shellcode, cls).__init__(name, bases, namespace)
        tokens = cls.__module__.split(".")
        if tokens[0] == base_package and tokens[1] != base_file:
            tokens.insert(-1, "any")
            print tokens
            cls.arch, cls.os = tokens[1:3]

# Metaclass to make sure a final shellcode cannot be subclassed.
class meta_shellcode_final(meta_shellcode):
    def __init__(cls, name, bases, namespace):
        for clazz in bases:
            if isinstance(clazz, meta_shellcode_final):
                raise TypeError("Class %s is final!" % clazz.__name__)
        super(meta_shellcode_final, cls).__init__(name, bases, namespace)

# This method is the reason why it's important to maintain consistent
# names and interfaces across platforms throughout the library.
def get_shellcode_class(arch, os, module, classname):
    """
    Get the requested shellcode class by classname, module, processor
    architecture and operating system.
    
    Tipically exploits would directly import the shellcode classes, but this
    helper function is useful if for some reason the platform must be set
    dynamically.
    
    @type  arch: str
    @param arch: Target processor architecture.
    
    @type  os: str
    @param os: Target operating system.
        Must be C{None} for OS agnostic shellcodes.
    
    @type  module: str
    @param module: Shellcode module name.
    
    @type  classname: str
    @param classname: Shellcode class name.
    
    @rtype:  class
    @return: Shellcode class.
    
    @raise ValueError: Invalid arguments.
    @raise NotImplementedError: The requested shellcode could not be found.
    """
    if "." in arch or arch.startswith("_"):
        raise ValueError("Bad processor architecture: %r" % arch)
    if os:
        if "." in os or os.startswith("_"):
            raise ValueError("Bad operating system: %r" % os)
        path = "shellgen.%s.%s.%s" % (arch, os, module)
    else:
        path = "shellgen.%s.%s" % (arch, module)
    if "." in module or module.startswith("_"):
        raise ValueError("Bad shellcode module: %r" % module)
    if "." in classname or classname.startswith("_"):
        raise ValueError("Bad shellcode class: %r" % classname)
    try:
        clazz = getattr( __import__(path, fromlist = [classname]), classname )
    except ImportError, e:
        msg = "Error loading module %s: %s" % (path, str(e))
        raise NotImplementedError(msg)
    except AttributeError, e:
        msg = "Error loading class %s.%s: %s" % (path, classname, str(e))
        raise NotImplementedError(msg)
    return clazz

# Warnings issued by this library are of this type.
class ShellcodeWarning (RuntimeWarning):
    pass

# Base shellcode class.
class Shellcode (object):

    # Autoloads the platform for our shellcodes.
    # Does nothing for user-defined shellcodes.
    __metaclass__ = meta_shellcode

    # Shellcode metadata.
    #
    # Supported values for "arch":
    #   any, mips, ppc, x86, x86_64
    #
    # Supported values for "os":
    #   aix, freebsd, hpux, irix, linux, netbsd,
    #   nt, openbsd, osx, solaris win32, win64
    #
    # Supported values for "requires" and "provides":
    #   pc, syscall, root
    #
    # Supported values for "qualities":
    #   payload, term_null, balance_stack, preserve_regs,
    #   stack_exec, no_stack, uses_heap, uses_seh, kernel
    #
    # Supported values for "encoding":
    #   nullfree, ascii, alpha, lower, upper, unicode
    #
    # Users may define their own values as well.
    #
    arch      = "any"
    os        = "any"
    requires  = []
    provides  = []
    qualities = []
    encoding  = []

    # TO DO: helper functions to check dependencies and constraints

    # Weak reference to the parent node.
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

    def _check_platform(self, other):
        arch = self.arch.lower()
        os   = self.os.lower()
        if not arch: arch = "any"
        if not os:     os = "any"
        if "any" not in (self.arch, other.arch) and self.arch != other.arch:
            msg = "Processor architectures don't match: %s and %s"
            msg = msg % (self.arch, other.arch)
            warnings.warn(msg, ShellcodeWarning)
        if "any" not in (self.os, other.os) and self.os != other.os:
            msg = "Operating systems don't match: %s and %s"
            msg = msg % (self.os, other.os)
            warnings.warn(msg, ShellcodeWarning)

    def __add__(self, other):
        if isinstance(other, str):    # bytes
            other = Raw(other, self.arch, self.os)
        elif not isinstance(other, Shellcode):
            return NotImplemented
        else:
            self._check_platform(other)
        return Concatenator(self, other)

    def __radd__(self, other):
        if isinstance(other, str):    # bytes
            other = Raw(other, self.arch, self.os)
        elif not isinstance(other, Shellcode):
            return NotImplemented
        else:
            self._check_platform(other)
        return Concatenator(other, self)

# Static shellcodes are defined when instanced and don't ever change.
class Static (Shellcode):

    # Subclasses MUST define "bytes".

    # Only Stagers may have stages. Don't override this method elsewhere.
    @property
    def stages(self):
        return []

    def compile(self):
        pass

# Raw shellcode class.
# An easy way to build custom shellcodes without having to think. :)
# Used automatically when concatenating Python strings to shellcodes.
class Raw (Static):

    # Don't subclass this class.
    __metaclass__= meta_shellcode_final

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
    __metaclass__= meta_shellcode_final

    def __init__(self, *children):
        super(Container, self).__init__()
        
         # Calculate metadata on runtime.
         # XXX still not sure about this feature...
#        self.requires  = property(self._collect_requires)
#        self.provides  = property(self._collect_provides)
#        self.qualities = property(self._collect_qualities)
#        self.encoding  = property(self._collect_encoding)
        
        # Build the list of children.
        parent = weakref.ref(self)
        self._children = list(children)
        for child in self._children:
            if not isinstance(child, Shellcode):
                raise TypeError(
                    "Expected Shellcode, got %s instead" % type(child))
        for child in self._children:
            if child.parent:
                msg = "Already had a parent: %r" % child.parent
                warnings.warn(msg, ShellcodeWarning)
            child._parent = parent

    def __iadd__(self, other):
        if isinstance(other, str):    # bytes
            other = Raw(other, self.arch, self.os)
        elif not isinstance(other, Shellcode):
            return NotImplemented
        else:
            self._check_platform(other)
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

    # returns the union of all requirements
    # TODO: revise this concept!
    def _collect_requires(self):
        requires = []
        for child in self.children:
            requires.extend(child.requires)
        return requires

    # returns the union of all provisions
    # TODO: revise this concept!
    def _collect_provides(self):
        provides = []
        for child in self.children:
            provides.extend(child.provides)
        return provides

    # returns the union of all qualities
    def _collect_qualities(self):
        qualities = []
        for child in self.children:
            qualities.extend(child.qualities)
        return qualities

    # returns the intersection of all encodings
    def _collect_encodings(self):
        encodings = set()
        for child in self.encodings:
            encodings.intersection_update(child.encodings)
        return list(encodings)

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
