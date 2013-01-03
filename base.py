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

@type version: float
@var  version: Library version.
"""

__all__ = [
    "version", "get_shellcode_class", "get_available_platforms",
    "ShellcodeWarning",
    "Shellcode", "Dynamic", "Static", "Raw",
    "Container", "Concatenator", "Decorator", "Encoder", "Stager",
    "meta_shellcode", "meta_shellcode_final",
]

version = "0.1"

import weakref
import warnings

from os import listdir
from os.path import dirname, isdir, isfile, join

try:
    base_package, base_file = __name__.split(".")[-2:]
except Exception:
    raise ImportError("Trying to load %s outside of its package" % __file__)

base_dir = dirname(__file__)

class meta_shellcode(type):
    """
    Autodetects the platform from the package name if it's ours.
    User-defined shellcodes should set C{arch} and C{os} instead.

    Makes sure the shellcode metadata is properly defined.

    Also converts lists to tuples in shellcode metadata to make them read-only.
    """
    def __init__(cls, name, bases, namespace):
        super(meta_shellcode, cls).__init__(name, bases, namespace)

        # If the shellcode is built-in, get the arch and os automatically.
        tokens = cls.__module__.split(".")
        if tokens[0] == base_package and tokens[1] != base_file:
            tokens.insert(-1, "any")
            cls.arch, cls.os = tokens[1:3]

        # Validate and sanitize the metadata.
        # TODO: issue warnings when work had to be done!
        try:

            # Validate the processor architecture.
            if not cls.arch:
                cls.arch = "any"
            elif "." in cls.arch or cls.arch.startswith("_"):
                raise ValueError("Bad processor architecture: %r" % cls.arch)

            # Validate the operating system.
            if not cls.os:
                cls.os = "any"
            elif "." in cls.os or cls.os.startswith("_"):
                raise ValueError("Bad operating system: %r" % cls.os)

            # Convert strings to tuples.
            if type(cls.requires)  is str:   cls.requires = (cls.requires,)
            if type(cls.provides)  is str:   cls.provides = (cls.provides,)
            if type(cls.qualities) is str:  cls.qualities = (cls.qualities,)
            if type(cls.encoding)  is str:   cls.encoding = (cls.encoding,)

            # Make dependencies and constraints read-only and lowercase.
            cls.requires  = tuple(map(str.lower, cls.requires))
            cls.provides  = tuple(map(str.lower, cls.provides))
            cls.qualities = tuple(map(str.lower, cls.qualities))
            cls.encoding  = tuple(map(str.lower, cls.encoding))

        # On error raise an exception.
        except AttributeError, e:
            raise TypeError("Shellcode metadata missing: %s" % e)

class meta_shellcode_final(meta_shellcode):
    "Metaclass to make sure a final shellcode cannot be subclassed."
    def __init__(cls, name, bases, namespace):
        for clazz in bases:
            if isinstance(clazz, meta_shellcode_final):
                raise TypeError("Class %s is final!" % clazz.__name__)
        super(meta_shellcode_final, cls).__init__(name, bases, namespace)

#-----------------------------------------------------------------------------#

class ShellcodeWarning (RuntimeWarning):
    "Warnings issued by this library are of this type."

#-----------------------------------------------------------------------------#

# Helper function to resolve shellcode classes dynamically.
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
        Must be C{None} or C{"any"} for platform independent shellcodes.

    @type  os: str
    @param os: Target operating system.
        Must be C{None} or C{"any"} for OS independent shellcodes.

    @type  module: str
    @param module: Shellcode module name.

    @type  classname: str
    @param classname: Shellcode class name.

    @rtype:  class
    @return: Shellcode class.

    @raise ValueError: Invalid arguments.
    @raise NotImplementedError: The requested shellcode could not be found.
    """

    # None and "any" are the same.
    if arch is None:
        arch = "any"
    if os is None:
        os = "any"

    # Check the validity of the arguments.
    if "." in arch or arch.startswith("_"):
        raise ValueError("Bad processor architecture: %r" % arch)
    if "." in os or os.startswith("_"):
        raise ValueError("Bad operating system: %r" % os)
    if "." in module or module.startswith("_"):
        raise ValueError("Bad shellcode module: %r" % module)
    if "." in classname or classname.startswith("_"):
        raise ValueError("Bad shellcode class: %r" % classname)

    # Build the fully qualified module name.
    if os == "any":
        path = "shellgen.%s.%s" % (arch, module)
    else:
        path = "shellgen.%s.%s.%s" % (arch, os, module)

    # Load the class and return it.
    try:
        clazz = getattr( __import__(path, fromlist = [classname]), classname )
    except ImportError, e:
        msg = "Error loading module %s: %s" % (path, str(e))
        raise NotImplementedError(msg)
    except AttributeError, e:
        msg = "Error loading class %s.%s: %s" % (path, classname, str(e))
        raise NotImplementedError(msg)
    return clazz

def get_available_platforms():
    """
    Get the list of available architectures from built-in shellcodes.

    This operation involves accessing the filesystem, so you may want to cache
    the response.

    @rtype: list( tuple(str, str) )
    @return: List of available architectures from built-in shellcodes.
        Each element in the list is a tuple containing:
         - processor architecture
         - operating system
    """
    platform_list = []
    for arch_name in listdir(base_dir):
        if arch_name.startswith("."):
            continue
        arch_dir = join(base_dir, arch_name)
        if not isdir(arch_dir) or not isfile(join(arch_dir, "__init__.py")):
            continue
        check_for_any = True
        for os_name in listdir(arch_dir):
            if os_name.startswith("."):
                continue
            os_dir = join(arch_dir, os_name)
            if isdir(os_dir) and isfile(join(os_dir, "__init__.py")):
                platform_list.append( (arch_name, os_name) )
            elif check_for_any:
                check_for_any = False
                platform_list.append( (arch_name, "any") )
    platform_list.sort()
    return platform_list

def autodetect_encoding(bytes):
    """
    Tries to autodetect the encoding of the given shellcode bytes.

    Currently the following encodings are detected:
     - C{term_null}
     - C{nullfree}
     - C{ascii}
     - C{alpha}
     - C{lower}
     - C{upper}
     - C{unicode}

    @note: The detection for Unicode is only for shellcodes encoded using the
        Venetian technique. It cannot tell if the shellcode would actually
        survive the codepage translation.

    @type  bytes: str
    @param bytes: Compiled bytecode to test for encodings.

    @rtype:  tuple(str)
    @return: Encoding constraints for this shellcode.
    """
    bytes = self.bytes
    encoding = []
    if "\x00" not in bytes:
        encoding.append("nullfree")
    elif bytes.endswith("\x00") and "\x00" not in bytes[:-1]:
        encoding.append("term_null")
    try:
        if bytes == bytes.encode("ascii"):
            encoding.append("ascii")
            if all( (x == "\x00" or x.isalnum() for x in bytes) ):
                encoding.append("alpha")
    except Exception:
        pass
    if bytes == bytes.lower():
        encoding.append("lower")
    if bytes == bytes.upper():
        encoding.append("upper")
    if len(bytes) & 1 == 0 and \
            all( ( bytes[i] == "\x00" for i in xrange(0, len(bytes), 2) ) ):
        encoding.append("unicode")
    return tuple(encoding)

#-----------------------------------------------------------------------------#

class Shellcode (object):
    """
    Base shellcode type.

    @type arch: str
    @cvar arch: Processor architecture supported by this shellcode.
        Use C{"any"} for architecture independent shellcodes.

    @type os: str
    @cvar os: Operating system.
        Use C{"any"} for platform independent shellcodes.

    @type requires: tuple(str)
    @cvar requires: Features required by this shellcode.

    @type provides: tuple(str)
    @cvar provides: Features provided by this shellcodes.

    @type qualities: tuple(str)
    @cvar qualities: Runtime characteristics of this shellcode.

    @type encoding: tuple(str)
    @cvar encoding: Encoding constraints for this shellcode.

    @type parent: L{Container}
    @ivar parent: Parent shellcode.

    @type bytes: str
    @ivar bytes: Compiled bytecode for this shellcode.
        May raise an exception on compilation errors.

    @type length: int
    @ivar length: Length of the compiled bytecode for this shellcode.
        May raise an exception on compilation errors.

    @type stages: list(str)
    @ivar stages: Compiled bytecode for this shellcode's stages.
        Empty list if this shellcode is not a L{Stager}.
        May raise an exception on compilation errors.

    @type children: list(L{Shellcode})
    @ivar children: Child shellcodes.
        Empty list if this shellcode is not a L{Container}.
    """

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
    #   payload, preserve_regs, stack_balanced, stack_exec, no_stack,
    #   uses_heap, heap_exec, uses_seh, kernel
    #
    # Supported values for "encoding":
    #   term_null, nullfree, ascii, alpha, lower, upper, unicode
    #
    # Users may define their own values as well.
    #
    arch      = "any"
    os        = "any"
    requires  = ()
    provides  = ()
    qualities = ()
    encoding  = ()

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

    def compile(self, variables = None):
        """
        Compile this shellcode, and its children and stages if it has any.

        @type  variables: dict
        @param variables: Optional dictionary of compilation variables.
            Expect it to be modified in place by this method on return.
        """
        raise NotImplementedError("Subclasses MUST implement this method!")

    def clean(self):
        "Clean the compilation of this shellcode."
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

    def __str__(self):
        return self.bytes

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

    def add_requirement(self, requirement):
        """
        Add the given requirement on runtime.

        @see: L{requires}

        @type  requirement: str
        @param requirement: Requirement.
        """
        if requirement not in self.requires:
            self.requires = self.requires + (requirement,)

    def remove_requirement(self, requirement):
        """
        Remove the given requirement on runtime.

        @see: L{requires}

        @type  requirement: str
        @param requirement: Requirement.
        """
        if requirement in self.requires:
            tmp = list(self.requires)
            tmp.remove(requirement)
            self.requires = tuple(tmp)

    def add_feature(self, feature):
        """
        Add the given provided feature on runtime.

        @see: L{provides}

        @type  feature: str
        @param feature: Feature.
        """
        if feature not in self.provides:
            self.provides = self.provides + (feature,)

    def remove_feature(self, feature):
        """
        Remove the given provided feature on runtime.

        @see: L{provides}

        @type  feature: str
        @param feature: Feature.
        """
        if feature in self.provides:
            tmp = list(self.provides)
            tmp.remove(feature)
            self.provides = tuple(tmp)

    def add_quality(self, quality):
        """
        Add the given runtime characteristic on runtime.

        @see: L{qualities}

        @type  quality: str
        @param quality: Runtime characteristic.
        """
        if quality not in self.qualities:
            self.qualities = self.qualities + (quality,)

    def remove_quality(self, quality):
        """
        Remove the given runtime characteristic on runtime.

        @see: L{qualities}

        @type  quality: str
        @param quality: Runtime characteristic.
        """
        if quality in self.qualities:
            tmp = list(self.qualities)
            tmp.remove(quality)
            self.qualities = tuple(tmp)

    def add_encoding(self, encoding):
        """
        Add the given encoding constraint on runtime.

        @see: L{encoding}

        @type  encoding: str
        @param encoding: Encoding constraint.
        """
        if encoding not in self.encoding:
            self.encoding = self.encoding + (encoding,)

    def remove_encoding(self, encoding):
        """
        Remove the given encoding constraint on runtime.

        @see: L{encoding}

        @type  encoding: str
        @param encoding: Encoding constraint.
        """
        if encoding in self.encoding:
            tmp = list(self.encoding)
            tmp.remove(encoding)
            self.encoding = tuple(tmp)

#-----------------------------------------------------------------------------#

class Static (Shellcode):
    """
    Static shellcodes are defined when instanced and don't ever change.
    """

    # Subclasses MUST define "bytes".

    # Only Stagers may have stages. Don't override this method elsewhere.
    @property
    def stages(self):
        return []

    def compile(self, variables = None):
        pass

#-----------------------------------------------------------------------------#

class Raw (Static):
    """
    Static shellcode built from raw bytes provided by the user.

    An easy way to build custom shellcodes without having to think. :)

    Used automatically when concatenating Python strings to shellcodes.
    """

    # Don't subclass this class.
    __metaclass__= meta_shellcode_final

    def __init__(self, bytes, arch = "any", os = "any",
                 requires = None,  provides = None,
                 qualities = None, encoding = None):
        """
        @type  bytes: str
        @param bytes: Compiled bytecode for this shellcode.

        @type  arch: str
        @param arch: Processor architecture supported by this shellcode.
            Use C{"any"} for architecture independent shellcodes.

        @type  os: str
        @param os: Operating system.
            Use C{"any"} for platform independent shellcodes.

        @type  requires: list(str)
        @param requires: Features required by this shellcode.
            Defaults to no features.

        @type  provides: list(str)
        @param provides: Features provided by this shellcodes.
            Defaults to no features.

        @type  qualities: list(str)
        @param qualities: Runtime characteristics of this shellcode.
            Defaults to no characteristics.

        @type  encoding: list(str)
        @param encoding: Encoding constraints for this shellcode.
            Autodetected by default, see: L{autodetect_encoding}.
        """
        super(Raw, self).__init__()
        if arch:           self.arch = arch
        if os:               self.os = os
        if requires:   self.requires = requires
        if provides:   self.provides = provides
        if qualities: self.qualities = qualities
        if encoding:   self.encoding = encoding
        else:
            self.encoding = autodetect_encoding(bytes)
        self.bytes = bytes

#-----------------------------------------------------------------------------#

class Dynamic (Shellcode):
    """
    Dynamic shellcodes may change their bytecode every time they're compiled.
    This allows you to reconfigure them on the fly, and it allows the shellcode
    to randomize some or all of its bytecode on each use.
    """

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

    # Clear the cache.
    def clean(self):
        self._bytes = None

#-----------------------------------------------------------------------------#

class Container (Dynamic):
    """
    Containers may hold one or more child shellcodes. When compiled, all of
    the child shellcodes are compiled as well.
    """

    # Must be updated on object instances.
    _bytes    = None
    _stages   = None

    # Wraps on the compile() method to catch compilation errors.
    # Called from bytes() and stages() only.
    def __autocompile(self):

        # Create an empty dictionary to store the compilation variables.
        variables = {}

        # Compile the shellcode. Clear the cache on error.
        try:
            self.compile(variables)
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
        self.__autocompile()
        return self._bytes

    # Containers inherit the stages of its children.
    # Don't override this method elsewhere.
    @property
    def stages(self):

        # Returns previously cached compiled stages if available.
        if self._stages is not None:
            return self._stages

        # Compile and return the compiled stages.
        self.__autocompile()
        return self._stages

    @property
    def children(self):
        raise NotImplementedError("Containers MUST define \"children\"!")

    def compile_children(self, variables = None):
        "Helper method that compiles all children and their stages."
        bytes  = ""
        stages = []
        if variables is None:
            variables = {}
        for child in self._children:
            child.compile(variables)
            bytes += child.bytes
            stages.extend(child.stages)
        return bytes, stages

#-----------------------------------------------------------------------------#

class Concatenator (Container):
    "Simple concatenation of two or more shellcodes."

    # Don't subclass this class.
    __metaclass__= meta_shellcode_final

    def __init__(self, *children):
        super(Container, self).__init__()

         # Calculate metadata on runtime.
        self.requires  = property(self._collect_requires)
        self.provides  = property(self._collect_provides)
        self.qualities = property(self._collect_qualities)
        self.encoding  = property(self._collect_encoding)

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
    def compile(self, variables = None):
        """
        Compile and concatenate the child shellcodes and gather their stages.

        @type  variables: dict
        @param variables: Optional dictionary of compilation variables.
            Expect it to be modified in place by this method on return.
        """
        self._bytes, self._stages = self.compile_children(variables)

#-----------------------------------------------------------------------------#

class Decorator (Container):
    "Decorators wrap around a shellcode to modify its compilation."

    # Must be updated on object instances by the constructor.
    _child = None

    def __init__(self, child):
        """
        @type  child: L{Shellcode}
        @param child: Shellcode whose compilation will be modified.
        """
        self._child = child

    @property
    def child(self):
        return self._child

    @property
    def children(self):
        child = self.child
        if child is None:
            return []
        return [child]

    # Must set both self._bytes and self._stages.
    def compile(self, variables = None):
        raise NotImplementedError(
            "Decorators MUST implement the compile() method!")

#-----------------------------------------------------------------------------#

class Encoder (Decorator):
    """
    Encoders wrap around ashellcode to pass encoding restrictions, for example
    ASCII character filters or Unicode codepage conversions.
    """

    # Must set both self._bytes and self._stages.
    def compile(self, variables = None):
        raise NotImplementedError(
            "Encoders MUST implement the compile() method!")

#-----------------------------------------------------------------------------#

class Stager (Decorator):
    """
    Stagers split shellcode execution into load stages.
    """

    # Must set both self._bytes and self._stages.
    # Remember to check for inherited stages!
    def compile(self, variables = None):
        raise NotImplementedError(
            "Stagers MUST implement the compile() method!")

#-----------------------------------------------------------------------------#
