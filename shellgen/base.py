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

@type default_bad_chars: str
@var  default_bad_chars: Default list of bad characters for encoders.
"""

__all__ = [
    "version",
    "ShellcodeWarning",
    "get_shellcode_class", "get_available_platforms",
    "find_bad_chars", "default_bad_chars", "good_chars", "random_chars",
    "CompilerState",
    "Shellcode", "Dynamic", "Static", "Raw",
    "Container", "Concatenator", "Decorator", "Encoder", "Stager",
]

version = "0.1"

import sys
import random
import keyword
import weakref
import warnings
import functools

from os import listdir, path

# Get the path in the filesystem where this library is installed.
base_dir = path.abspath(path.dirname(__file__))

# For unit testing, fix the modules path and get our package and module name.
if __name__ == '__main__':
    sys.path.insert(0, path.join(base_dir, ".."))
    base_file = path.abspath(__file__)
    base_package = path.dirname(base_file).split(path.sep)[-1]
    base_file = path.splitext(path.basename(base_file))[0]

# When importing, get our package and module name.
# Fail if this file's been moved elsewhere.
else:
    try:
        base_package, base_file = __name__.split(".")[-2:]
    except Exception:
        msg = "Trying to load %s outside of its package" % __file__
        raise ImportError(msg)

# This method may be a little paranoid, but better safe than sorry!
def is_valid_module_path_component(token):
    "Validate strings to be used when importing modules dynamically."
    return not token.startswith("_") and not keyword.iskeyword(token) and \
        all( ( (x.isalnum() or x == "_") for x in token ) )

def meta_canonicalize_arch(arch, os, classname = None):
    "Canonicalizes arch and os. See L{meta_canonicalize}."

    # Validate the processor architecture.
    if not isinstance(arch, property):
        if not arch:
            arch = "any"
        elif not is_valid_module_path_component(arch):
            if classname:
                msg = "Bad processor architecture in %s: %r"
                msg = msg % (classname, arch)
            else:
                msg = "Bad processor architecture: %r"
                msg = msg % arch
            raise ValueError(msg)
        else:
            arch = arch.strip().lower()

    # Validate the operating system.
    if not isinstance(os, property):
        if not os:
            os = "any"
        elif not is_valid_module_path_component(os):
            if classname:
                msg = "Bad operating system in %s: %r"
                msg = msg % (classname, os)
            else:
                msg = "Bad operating system: %r"
                msg = msg % os
            raise ValueError(msg)
        else:
            os = os.strip().lower()

    return arch, os

def meta_canonicalize_tags(tags):
    "Canonicalizes tags. See L{meta_canonicalize}."

    # Ignore class properties.
    if isinstance(tags, property):
        return tags

    # Convert None and empty containers to 0-tuples.
    if not tags:
        tags = ()

    # Convert strings to 1-tuples of stripped, lowercase strings.
    # Unless they're multiple tags separated by commas or spaces or both.
    # Then they're treated like iterables (see below).
    elif type(tags) is str:
        if "," in tags:
            tags = tuple(tags.split(","))
        elif " " in tags or "\t" in tags:
            tags = tuple(tags.split())
        else:
            tags = (tags.strip().lower(),)

    # Convert string iterables to n-tuples of
    # stripped, lowercase, unique and sorted strings.
    if tags:
        tags = [x.strip().lower() for x in tags]
        tags = set(tags)
        tags = [x for x in tags if x]
        tags.sort()
        tags = tuple(tags)

    # Return the canonicalized tags.
    return tags

def meta_canonicalize(cls):
    "Canonicalizes the metadata to simplify the logic when accessing it."

    # Canonicalize the arch and os.
    try:
        clsname = cls.__name__              # class
    except AttributeError:
        clsname = cls.__class__.__name__    # instance
    cls.arch, cls.os = meta_canonicalize_arch(cls.arch, cls.os, clsname)

    # Canonicalize the tags.
    fix_tags = meta_canonicalize_tags
    cls.requires  = fix_tags(cls.requires)
    cls.provides  = fix_tags(cls.provides)
    cls.qualities = fix_tags(cls.qualities)
    cls.encoding  = fix_tags(cls.encoding)

    # TODO: Make sure there are no inconsistencies in the metadata.

def meta_autodetect_platform(cls):
    """
    Dark magic to autodetect the platform for built-in shellcodes.

    User-defined shellcodes must define "arch" and "os".
    """
    abspath = path.abspath
    join = path.join
    split = path.split
    splitext = path.splitext
    sep = path.sep
    module = cls.__module__
    if module != "__main__":
        tokens = cls.__module__.split(".")
        if len(tokens) < 2 or tokens[0] != base_package or \
                              tokens[1] == base_file:
            return
        tokens.insert(-1, "any")
        tokens = tokens[1:3]
    else:
        module = abspath(sys.modules[module].__file__)
        if not module.startswith(base_dir):
            return
        tokens = module.split(sep)
        tokens = tokens[len(base_dir.split(sep)):-1]
        while len(tokens) < 2:
            tokens.append("any")
    cls.arch, cls.os = tokens

def meta_compile(compile):
    "Wraps the compile() method to do dark magic, see L{meta_shellcode}."

    @functools.wraps(compile)
    def compile_wrapper(self, state = None):
        if state is None:
            state = CompilerState()
        state.next_piece()
        if hasattr(self, "_compile_hook"):
            return self._compile_hook(compile, state)
        return compile(self, state)

    return compile_wrapper

class meta_shellcode(type):
    "Does a lot of dark magic to simplify writing a new shellcode."

    def __init__(cls, name, bases, namespace):
        super(meta_shellcode, cls).__init__(name, bases, namespace)
        try:

            # If the shellcode is built-in, get the arch and os automatically.
            meta_autodetect_platform(cls)

            # Canonicalize the metadata.
            meta_canonicalize(cls)

            # Wrap the compile() method if it's a new one.
            if cls.compile not in (
                        getattr(b, "compile", None) for b in cls.__bases__):
                cls.compile = meta_compile(cls.compile)
            ##elif cls.__name__ not in ("Raw", "Container"):
            ##    warnings.warn(
            ##        "Not setting wrapper on class %s" % cls.__name__)

        # On error raise an exception.
        except Exception, e:
            msg = "Metadata error in shellcode %s: %s"
            msg = msg % (cls.__name__, e)
            raise TypeError(msg)

class meta_shellcode_final(meta_shellcode):
    "Metaclass to make sure a final shellcode cannot be subclassed."
    def __init__(cls, name, bases, namespace):
        for clazz in bases:
            if isinstance(clazz, meta_shellcode_final):
                raise TypeError("Class %s is final" % clazz.__name__)
        super(meta_shellcode_final, cls).__init__(name, bases, namespace)

class meta_shellcode_static(meta_shellcode):
    "Makes sure the user wasn't so crazy to have compile() in a Static."
    def __init__(cls, name, bases, namespace):
        super(meta_shellcode_static, cls).__init__(name, bases, namespace)
        if cls.__module__ != __name__ and cls.compile not in (
                    getattr(b, "compile", None) for b in cls.__bases__):
            msg = (
                "What's %s.compile doing there?"
                " Are you nuts?!"
                " *Slap in the wrist*"
            ) % cls.__name__
            raise TypeError(msg)

class meta_shellcode_raw(meta_shellcode_static):
    "Combination of L{meta_shellcode_static} and L{meta_shellcode_final}."
    def __init__(cls, name, bases, namespace):
        for clazz in bases:
            if isinstance(clazz, meta_shellcode_raw):
                raise TypeError("Class %s is final" % clazz.__name__)
        super(meta_shellcode_raw, cls).__init__(name, bases, namespace)

def copy_classes(all, name, namespace):
    """
    Helper function to redefine classes imported from another module,
    to have L{meta_shellcode} update the metadata automatically.

    Example::
        # In shellgen.x86_64.nop
        from shellgen.x86.nop import *
        from shellgen.x86.nop import __all__
        from shellgen.base import copy_classes
        copy_classes(__all__, __name__, vars())

    @type  all: list(str)
    @param all: The __all__ value for the calling module.

    @type  name: str
    @param name: The __name__ value for the calling module.

    @type  namespace: dict
    @param namespace: The namespace of the calling module,
        namely, the result of calling C{vars()}.
    """

    # For all exported symbols...
    for classname in all:

        # Get the object it refers to.
        clazz = namespace[classname]

        # If it's a shellcode class...
        if issubclass(clazz, Shellcode):

            # Create a subclass of it with the same name.
            clazz = clazz.__metaclass__(classname, (clazz,), {})

            # Set the correct module name.
            clazz.__module__ = name

            # Redetect the platform metadata.
            meta_autodetect_platform(clazz)

            # Save the new class in the module namespace.
            namespace[classname] = clazz

def print_shellcode_tree(shellcode, indent = 0):
    """
    Helper function to show the shellcode object tree.

    Useful for debugging.

    @type  shellcode: L{Shellcode}
    @param shellcode: Any shellcode.

    @type  indent: int
    @param indent: Indentation level.
    """

    # Make sure all we get are Shellcode instances.
    if not isinstance(shellcode, Shellcode):
        raise TypeError("Expected Shellcode, got %r instead" % type(shellcode))

    # Calculate the indentation space we'll need.
    space = "    " * (indent)

    # Show the shellcode name and metadata.
    print "%s%s" % (space, shellcode.__class__.__name__)
    print "%s* Platform:  %s (%s)" % (space, shellcode.os, shellcode.arch)
    if shellcode.requires:
        print "%s* Requires:  %s" % (space, ", ".join(list(shellcode.requires)))
    if shellcode.provides:
        print "%s* Provides:  %s" % (space, ", ".join(list(shellcode.provides)))
    if shellcode.qualities:
        print "%s* Qualities: %s" % (space, ", ".join(list(shellcode.qualities)))
    if shellcode.encoding:
        print "%s* Encoding:  %s" % (space, ", ".join(list(shellcode.encoding)))

    # Show the number of children and stages.
    if shellcode.children:
        print "%s* Children:  %d" % (space, len(shellcode.children))
    if shellcode.stages:
        print "%s* Stages:    %d" % (space, len(shellcode.stages))

    # Show the shellcode bytes and length.
    bytes = None
    if isinstance(shellcode, Static):           # For static shellcodes,
        bytes  = shellcode.bytes                #  get the bytes and length
        length = shellcode.length               #  directly.
    elif hasattr(shellcode, "_Dynamic__bytes"): # For dynamic shellcodes,
        bytes = shellcode._Dynamic__bytes       #  get them from the cache.
        if bytes:
            length = len(bytes)
        else:
            length = 0
    if bytes is not None:
        if len(bytes) != length:
            warnings.warn("Bad length for %s" % shellcode.__class__.__name__)
        bytes = bytes.encode("hex")
        if len(bytes) > 32:
            bytes = bytes[:16] + "..." + bytes[-16:]
        print "%s* Length:    %d" % (space, length)
        if bytes:
            print "%s* Bytes:     %s" % (space, bytes)

    # Leave an empty line between shellcodes.
    print

    # Recursively show the children, indented.
    indent += 1
    for child in shellcode.children:
        print_shellcode_tree(child, indent)

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

    # Canonicalize the arch and os.
    arch, os = meta_canonicalize_arch(arch, os)

    # Validate the module and classname.
    if not is_valid_module_path_component(module):
        raise ValueError("Bad shellcode module: %r" % module)
    if not is_valid_module_path_component(classname):
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
    isdir  = path.isdir
    isfile = path.isfile
    join   = path.join
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
    encoding = []
    if isinstance(bytes, Shellcode):
        bytes = bytes.bytes
    if not bytes:
        bytes = ""
    if "\x00" not in bytes:
        encoding.append("nullfree")
    elif bytes.endswith("\x00") and "\x00" not in bytes[:-1]:
        encoding.append("term_null")
    try:
        if bytes == bytes.encode("ascii"):
            encoding.append("ascii")
            if all( ((x == "\x00" or x.isalnum()) for x in bytes) ):
                encoding.append("alpha")
    except Exception:
        pass
    if bytes == bytes.lower():
        encoding.append("lower")
    if bytes == bytes.upper():
        encoding.append("upper")
    if len(bytes) & 1 == 0:
        if all( ( bytes[i] == "\x00" for i in xrange(1, len(bytes), 2) ) ):
            encoding.append("unicode")
            if bytes.endswith("\x00\x00") and not all(
                (bytes[i] == "\x00" for i in xrange(0, len(bytes), 2) ) ):
                    encoding.append("term_null")
    return tuple(sorted(encoding))

def find_bad_chars(bytes, bad_chars = None):
    """
    Test the given bytecode against a list of bad characters.

    @type  bytes: str
    @param bytes: Compiled bytecode to test for bad characters.

    @type  bad_chars: str
    @param bad_chars: Bad characters to test.
        Defaults to L{default_bad_chars}.

    @rtype:  str
    @return: Bad characters present in the bytecode.
    """
    if bad_chars is None:
        bad_chars = default_bad_chars
    return "".join( (c for c in bad_chars if c in bytes) )

default_bad_chars = '\x00\t\n\r\x1a !"#$%&\'()+,./:;=[\\]`{|}'

def good_chars(bad_chars = None):
    """
    Take a bad chars list and generate the opposite good chars list.

    This can be useful for testing how the vulnerable program filters the
    characters we feed it.

    @type  bad_chars: str
    @param bad_chars: Bad characters to test.
        Defaults to L{default_bad_chars}.

    @rtype:  str
    @return: Good characters.
    """
    if bad_chars is None:
        bad_chars = default_bad_chars
    bad_list = set( map(ord, bad_chars) )
    return "".join( (chr(c) for c in xrange(256) if c not in bad_list) )

def random_chars(length, bad_chars = None):
    """
    Generate a string of random characters, avoiding bad characters.

    This can be useful to randomize the payload of our exploits.

    @type  length: int
    @param length: How many characters to generate.

    @type  bad_chars: str
    @param bad_chars: Bad characters to test.
        Defaults to L{default_bad_chars}.

    @rtype:  str
    @return: String of random characters.
    """
    if bad_chars is None:
        bad_chars = default_bad_chars
    c = good_chars(bad_chars)
    if not c:
        raise ValueError("All characters are bad!")
    m = len(c) - 1
    randint = random.randint
    return "".join( ( c[randint(0, m)] for i in xrange(length) ) )

#-----------------------------------------------------------------------------#

class CompilerState (object):
    """
    Compiler state variables.

    They are passed to and modified in place by all pieces of shellcode
    during compilation, in concatenation order.

    @type shared: dict
    @ivar shared: Shared variables.
        This is used to communicate things to all pieces of the shellcode.

    @type  current: dict
    @param current: Current state.
        This is used by this piece of shellcode to communicate things to
        the next piece, but only to the next piece.

    @type  previous: dict
    @param previous: Previous state.
        This is used by the previous piece of shellcode to communicate things
        to this piece, but only to this piece.
    """
    def __init__(self):
        self.shared   = {}
        self.current  = {}
        self.previous = {}

    def next_piece(self):
        "Called when moving to the next piece of shellcode."
        self.previous = self.current
        self.current  = {}

    def requires_nullfree(self):
        """
        @rtype:  bool
        @return: C{True} if the shellcode is required to be null free,
            C{False} otherwise.
        """
        return (
            "nullfree" in self.shared.get("encoding", "") or
            "\x00" in self.shared.get("badchars", "")
        )

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

    @type stages: list(L{Shellcode})
    @ivar stages: List of subsequent shellcode stages.
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

    # Only Containers may have children.
    @property
    def children(self):
        return []

    # Only Containers may have stages.
    @property
    def stages(self):
        return []

    # Default implementation causes the code to be compiled.
    # Subclasses may override this to return a constant when feasable.
    @property
    def length(self):
        return len(self.bytes)

    def compile(self, state = None):
        """
        Compile this shellcode.

        @type  state: L{CompilerState}
        @param state: Compilation variables.

        @rtype:  str
        @return: Compiled bytecode.
        """
        raise NotImplementedError("Subclasses MUST implement this method!")

    def clean(self):
        "Clean the compilation of this shellcode."
        pass

    def _check_platform(self, other):
        """
        Verify that this and another shellcode have compatible platforms.

        This means they are for the same plaform, or at least one of them is
        platform independent.

        @type  other: L{Shellcode}
        @param other: Another shellcode.

        @return: There is no return value.
            Warnings are raised if the platforms don't match.
        """
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
        requires = meta_canonicalize_tags(requirement)
        requires = meta_canonicalize_tags(self.requires + requires)
        self.requires = requires

    def remove_requirement(self, requirement):
        """
        Remove the given requirement on runtime.

        @see: L{requires}

        @type  requirement: str
        @param requirement: Requirement.
        """
        tmp = list(self.requires)
        for x in meta_canonicalize_tags(requirement):
            if x in tmp:
                tmp.remove(x)
        self.requires = tuple(tmp)

    def add_feature(self, feature):
        """
        Add the given provided feature on runtime.

        @see: L{provides}

        @type  feature: str
        @param feature: Feature.
        """
        provides = meta_canonicalize_tags(feature)
        provides = meta_canonicalize_tags(self.provides + provides)
        self.provides = provides

    def remove_feature(self, feature):
        """
        Remove the given provided feature on runtime.

        @see: L{provides}

        @type  feature: str
        @param feature: Feature.
        """
        tmp = list(self.provides)
        for x in meta_canonicalize_tags(feature):
            if x in tmp:
                tmp.remove(x)
        self.provides = tuple(tmp)

    def add_quality(self, quality):
        """
        Add the given runtime characteristic on runtime.

        @see: L{qualities}

        @type  quality: str
        @param quality: Runtime characteristic.
        """
        qualities = meta_canonicalize_tags(quality)
        qualities = meta_canonicalize_tags(self.qualities + qualities)
        self.qualities = qualities

    def remove_quality(self, quality):
        """
        Remove the given runtime characteristic on runtime.

        @see: L{qualities}

        @type  quality: str
        @param quality: Runtime characteristic.
        """
        tmp = list(self.qualities)
        for x in meta_canonicalize_tags(quality):
            if x in tmp:
                tmp.remove(x)
        self.qualities = tuple(tmp)

    def add_encoding(self, encoding):
        """
        Add the given encoding constraint on runtime.

        @see: L{encoding}

        @type  encoding: str
        @param encoding: Encoding constraint.
        """
        encoding = meta_canonicalize_tags(encoding)
        encoding = meta_canonicalize_tags(self.encoding + encoding)
        self.encoding = encoding

    def remove_encoding(self, encoding):
        """
        Remove the given encoding constraint on runtime.

        @see: L{encoding}

        @type  encoding: str
        @param encoding: Encoding constraint.
        """
        tmp = list(self.encoding)
        for x in meta_canonicalize_tags(encoding):
            if x in tmp:
                tmp.remove(x)
        self.encoding = tuple(tmp)

#-----------------------------------------------------------------------------#

class Static (Shellcode):
    "Static shellcodes are defined when instanced and don't ever change."

    # Don't add a compile() method.
    __metaclass__ = meta_shellcode_static

    # Subclasses MUST define "bytes".
    bytes = ""

    def compile(self, state = None):
        return self.bytes

#-----------------------------------------------------------------------------#

class Raw (Static):
    """
    Static shellcode that comes from raw bytes provided by the user.

    It's an easy way to build custom shellcodes without having to think. :)

    Used automatically when concatenating strings to shellcodes.
    """

    # Don't subclass this class. Also don't add a compile() method.
    __metaclass__= meta_shellcode_raw

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

        # Convert another Shellcode instance into Raw.
        # Could be useful to make dynamic shellcodes become static.
        # Arguments still override the metadata even in this case.
        if isinstance(bytes, Shellcode):
            if arch is None:           arch = bytes.arch
            if os is None:               os = bytes.os
            if requires is None:   requires = bytes.requires
            if provides is None:   provides = bytes.provides
            if qualities is None: qualities = bytes.qualities
            if encoding is None:   encoding = bytes.encoding
            bytes = bytes.bytes

        # Check the bytecode is a string.
        if not isinstance(bytes, str):
            raise TypeError("Expected str, got %s instead" % type(bytes))

        # Arguments override the metadata.
        if arch is not None:           self.arch = arch
        if os is not None:               self.os = os
        if requires is not None:   self.requires = requires
        if provides is not None:   self.provides = provides
        if qualities is not None: self.qualities = qualities
        if encoding is not None:   self.encoding = encoding
        else:
            # Default for encoding is autodetection.
            self.encoding = autodetect_encoding(bytes)

        # Store the bytecode.
        self.bytes = bytes

        # Sanitize the metadata because it may come from the user.
        meta_canonicalize(self)

#-----------------------------------------------------------------------------#

class Dynamic (Shellcode):
    """
    Dynamic shellcodes may change their bytecode every time they're compiled.
    This allows you to reconfigure them on the fly, and it allows the shellcode
    to randomize some or all of its bytecode on each use.
    """

    # Updated on object instances each time the compile() method is called.
    __bytes = None

    @property
    def bytes(self):

        # Returns previously cached bytecode if available.
        if self.__bytes is not None:
            return self.__bytes

        # Compile the shellcode.
        self.compile()

        # If compilation fails, raise an exception.
        if self.__bytes is None:
            msg = (
                "Compilation failed. Did you forget"
                " to return the bytecode at %s.compile?"
            ) % self.__class__.__name__
            raise RuntimeError(msg)

        # Return the compiled bytes.
        return self.__bytes

    def clean(self):

        # Clear the cache.
        self.__bytes = None

    def _compile_hook(self, compile, state = None):
        """
        Hooks the L{compile} method to save the bytecode in the cache.
        Called from L{meta_compile}.

        @type  compile: method
        @param compile: Implementation of L{compile}
            before being wrapped by L{meta_compile}.

        @type  state: L{CompilerState}
        @param state: Compilation variables.

        @rtype: str
        @return: Compiled bytecode.
        """

        # Create a new compiler state if needed.
        if state is None:
            state = CompilerState()

        # Compile the shellcode. Clear the cache on error.
        try:
            self.__bytes = compile(self, state)
        except:
            self.clean()
            raise

        # Return the shellcode.
        return self.__bytes

    def compile(self, state = None):
        raise NotImplementedError(
            "Dynamic shellcodes MUST implement the compile() method!")

#-----------------------------------------------------------------------------#

class Container (Dynamic):
    """
    Containers may hold one or more child shellcodes. When compiled, all of
    the child shellcodes are compiled as well.
    """

    # Updated on object instances.
    _children = None
    _stages   = None

    def __init__(self, *children):

        # Populate the list of children.
        self._children = []
        parent = weakref.ref(self)
        previous = self
        for child in children:
            if isinstance(child, str):    # bytes
                child = Raw(child, self.arch, self.os)
            elif not isinstance(child, Shellcode):
                raise TypeError(
                    "Expected Shellcode, got %s instead" % type(child))
            elif child.parent:
                msg = "Already had a parent: %r" % child.parent
                warnings.warn(msg, ShellcodeWarning)
            child._parent = parent
            self._children.append(child)
            previous._check_platform(child)
            previous = child

    # Containers inherit the stages of its children.
    @property
    def stages(self):

        # Returns previously cached stages if available.
        if self._stages is not None:
            return self._stages

        # Gather the stages of the children.
        stages = []
        for child in self.children:
            stages.extend(child.stages)

        # Keep the stages in the cache.
        self._stages = stages

        # Return the stages.
        return self._stages

    @property
    def children(self):

        if self._children is None:
            msg = "Did you forget to call the superclass constructor in %s?"
            msg = msg % self.__class__.__name__
            raise NotImplementedError(msg)

        # TODO make readonly somehow?
        # returning a copy would work but it's inefficient
        return self._children

    def clean(self):

        # Clear both caches.
        self._stages = None
        super(Container, self).clean()

    def compile_children(self, state = None):
        """
        Helper method that compiles all children and their stages.

        @type  state: dict
        @param state: Optional compilation state.

        @rtype:  str
        @return: Compiled bytecode.
        """
        if state is None:
            state = CompilerState()
        bytes = ""
        for child in self.children:
            bytes += child.compile(state)
        return bytes

#-----------------------------------------------------------------------------#

class Concatenator (Container):
    "Simple concatenation of two or more shellcodes."

    # Don't subclass this class.
    __metaclass__= meta_shellcode_final

    def __init__(self, *children):

        # Populate the list of children.
        super(Concatenator, self).__init__(*children)

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

    # If all children are compatible with the same architecture, return it.
    # Otherwise return "any".
    @property
    def arch(self):
        arch = "any"
        for child in self.children:
            if child.arch != "any":
                if arch == "any":
                    arch = child.arch
                elif child.arch != arch:
                    arch = "any"
                    break
        return arch

    # If all children are compatible with the same OS, return it.
    # Otherwise return "any".
    @property
    def os(self):
        os = "any"
        for child in self.children:
            if child.os != "any":
                if os == "any":
                    os = child.os
                elif child.os != os:
                    os = "any"
                    break
        return os

    # Returns the union of all requirements.
    # TODO: revise this concept!
    @property
    def requires(self):
        requires = set()
        for child in self.children:
            requires.update(child.requires)
        return sorted(requires)

    # Returns the union of all provisions.
    # TODO: revise this concept!
    @property
    def provides(self):
        provides = set()
        for child in self.children:
            provides.update(child.provides)
        return sorted(provides)

    # Returns the union of all qualities.
    @property
    def qualities(self):
        qualities = set()
        for child in self.children:
            qualities.update(child.qualities)
        return sorted(qualities)

    # Returns the intersection of all encodings.
    @property
    def encoding(self):
        encoding = set()
        update = encoding.update
        for child in self.children:
            update(child.encoding)
            update = encoding.intersection_update
        return sorted(encoding)

    # Concatenate all bytes.
    def compile(self, state):
        state.current = state.previous
        return self.compile_children(state)

#-----------------------------------------------------------------------------#

class Decorator (Container):
    "Decorators wrap around a shellcode to modify its compilation."

    def __init__(self, child):
        """
        @type  child: L{Shellcode}
        @param child: Shellcode whose compilation will be modified.
        """
        super(Decorator, self).__init__(child)

    @property
    def child(self):
        children = self.children
        if len(children) != 1:
            msg = (
                "Decorators can only have one child."
                " Try concatenating them before passing them to %s()."
            ) % self.__class__.__name__
            raise RuntimeError(msg)
        return children[0]

    def compile(self, state):
        raise NotImplementedError(
            "Decorators MUST implement the compile() method!")

#-----------------------------------------------------------------------------#

class Encoder (Decorator):
    """
    Encoders wrap around ashellcode to pass encoding restrictions, for example
    ASCII character filters or Unicode codepage conversions.
    """

    def compile(self, state):
        raise NotImplementedError(
            "Encoders MUST implement the compile() method!")

#-----------------------------------------------------------------------------#

class Stager (Dynamic):
    "Stagers split shellcode execution into load stages."

    # Updated on object instances.
    _next_stage = None

    def __init__(self, next_stage):
        self._next_stage = next_stage

    @property
    def next_stage(self):
        return self._next_stage

    # Stagers also inherit the stages of its children.
    @property
    def stages(self):
        next_stage = self.next_stage
        if next_stage is None:
            msg = "Did you forget to call the superclass constructor in %s?"
            msg = msg % self.__class__.__name__
            raise NotImplementedError(msg)
        stages = [next_stage]
        stages.extend( next_stage.stages )

    def compile(self, state):
        raise NotImplementedError(
            "Stagers MUST implement the compile() method!")

#-----------------------------------------------------------------------------#

# Unit test.
if __name__ == '__main__':
    from shellgen import *
    def test():

        # Static subclasses shouldn't define their own compile() method.
        try:
            class TestStaticCompile (Static):
                def compile(self, state):
                    print "Static.compile() suppression failed!"

            print "Static() verification failed!"
            TestStaticCompile().compile()
        except TypeError:
            ##raise
            pass

        # Raw shouldn't be subclassed.
        try:
            class TestSubclassedRaw (Raw):
                pass
            print "meta_shellcode_raw() verification failed!"
        except TypeError:
            ##raise
            pass

        # Concatenator shouldn't be subclassed.
        try:
            class TestSubclassedConcatenator (Concatenator):
                pass
            print "meta_shellcode_final() verification failed!"
        except TypeError:
            ##raise
            pass

        # Test the canonicalization of the metadata in a class.
        class TestCanonicalization(Static):
            requires = "requires"
            provides = ["   pro", "VideS", "PRO   "]
            qualities = "  quali, ties  "
            encoding = (x for x in ("en", "co", "ding"))
            bytes = ""
        assert TestCanonicalization.requires  == ("requires",)
        assert TestCanonicalization.provides  == ("pro", "vides")
        assert TestCanonicalization.qualities == ("quali", "ties")
        assert TestCanonicalization.encoding  == ("co", "ding", "en")

        # Test editing the metadata in an instance.
        t = TestCanonicalization()
        t.add_requirement("re")
        t.remove_requirement("fake")
        t.remove_requirement("requires")
        t.add_requirement("quires")
        assert t.requires == ("quires", "re")
        assert t.requires != TestCanonicalization.requires
        t.remove_feature("fake")
        t.add_feature(" PRO VIDES ")
        t.add_feature("\tPRO\tVIDES\t")
        t.add_feature("PrO, VideS")
        assert t.provides == TestCanonicalization.provides
        t.remove_feature("pro")
        t.add_feature("Feature")
        assert t.provides == ("feature", "vides")
        assert t.provides != TestCanonicalization.provides
        t.add_quality("ti")
        t.remove_quality("fake")
        t.add_quality("es")
        t.remove_quality("ties")
        assert t.qualities == ("es", "quali", "ti")
        assert t.qualities != TestCanonicalization.qualities
        t.add_encoding("EN")
        t.add_encoding("  co  ")
        t.add_encoding("\tDiNg\t")
        t.add_encoding(" enco  di  ")
        t.add_encoding(" n, g ")
        assert t.encoding == ("co", "di", "ding", "en", "enco", "g", "n")
        assert t.encoding != TestCanonicalization.encoding

        # Test the platform metadata.
        class TestArchAny(Static):
            provides = "multiarch"
            encoding = "unicode, nullfree"
            bytes = "TestArchAny"
        TestArchAny.arch = "any"
        TestArchAny.os = "windows"
        class TestOsAny(Static):
            provides = "multios"
            encoding = "unicode, nullfree"
            bytes = "TestOsAny"
        TestOsAny.arch = "x86"
        TestOsAny.os = "any"
        class TestArchOsAny(Static):
            provides = "multiarch, multios"
            encoding = "nullfree"
            bytes = "TestArchOsAny"
        TestArchOsAny.arch = "any"
        TestArchOsAny.os = "any"
        class TestArchOsSomething(Static):
            encoding = "ascii, nullfree"
            bytes = "TestArchOsSomething"
        TestArchOsSomething.arch = "x86"
        TestArchOsSomething.os = "windows"
        class TestArchIncompatible(Static):
            provides = "multios"
            encoding = "nullfree"
            bytes = "TestArchIncompatible"
        TestArchIncompatible.arch = "ppc"
        TestArchIncompatible.os = "any"
        class TestOsIncompatible(Static):
            provides = "multiarch"
            bytes = "TestOsIncompatible"
        TestOsIncompatible.arch = "any"
        TestOsIncompatible.os = "osx"
        class TestArchOsIncompatible(Static):
            encoding = "nullfree"
            bytes = "TestArchOsIncompatible"
        TestArchOsIncompatible.arch = "ppc"
        TestArchOsIncompatible.os = "osx"
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            test1  = TestArchAny() + TestOsAny() + TestArchOsAny()
            test1 += TestArchOsSomething()
            test2  = TestArchIncompatible() + TestOsIncompatible()
            test2 += TestArchOsIncompatible()
            assert not w
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            test3 = test1 + test2
            assert w
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            TestArchAny() + TestOsIncompatible()
            assert w
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            TestOsAny() + TestArchIncompatible()
            assert w
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            TestArchOsSomething() + TestArchOsIncompatible()
            assert w

        # Test concatenation and metadata inheritance.
        # (This is a lame test, I know. I got lazy, sorry!)
        from shellgen.base import print_shellcode_tree
        ##print_shellcode_tree( test3 ) # For updating the test...
        ##sys.exit(0)                   # For updating the test...
        from StringIO import StringIO
        stdout = sys.stdout
        capture = StringIO()
        try:
            sys.stdout = capture
            print_shellcode_tree( test3 )
        finally:
            sys.stdout = stdout
        assert capture.getvalue() == (
"""Concatenator
* Platform:  any (any)
* Provides:  multiarch, multios
* Children:  2

    Concatenator
    * Platform:  windows (x86)
    * Provides:  multiarch, multios
    * Encoding:  nullfree
    * Children:  3

        Concatenator
        * Platform:  windows (x86)
        * Provides:  multiarch, multios
        * Encoding:  nullfree, unicode
        * Children:  2

            TestArchAny
            * Platform:  windows (any)
            * Provides:  multiarch
            * Encoding:  nullfree, unicode
            * Length:    11
            * Bytes:     5465737441726368416e79

            TestOsAny
            * Platform:  any (x86)
            * Provides:  multios
            * Encoding:  nullfree, unicode
            * Length:    9
            * Bytes:     546573744f73416e79

        TestArchOsAny
        * Platform:  any (any)
        * Provides:  multiarch, multios
        * Encoding:  nullfree
        * Length:    13
        * Bytes:     54657374417263684f73416e79

        TestArchOsSomething
        * Platform:  windows (x86)
        * Encoding:  ascii, nullfree
        * Length:    19
        * Bytes:     5465737441726368...6f6d657468696e67

    Concatenator
    * Platform:  osx (ppc)
    * Provides:  multiarch, multios
    * Children:  3

        TestArchIncompatible
        * Platform:  any (ppc)
        * Provides:  multios
        * Encoding:  nullfree
        * Length:    20
        * Bytes:     5465737441726368...6d70617469626c65

        TestOsIncompatible
        * Platform:  osx (any)
        * Provides:  multiarch
        * Length:    18
        * Bytes:     546573744f73496e...6d70617469626c65

        TestArchOsIncompatible
        * Platform:  osx (ppc)
        * Encoding:  nullfree
        * Length:    22
        * Bytes:     5465737441726368...6d70617469626c65

""")
        test3.compile()
        assert test3.bytes == (
            "TestArchAny"
            "TestOsAny"
            "TestArchOsAny"
            "TestArchOsSomething"
            "TestArchIncompatible"
            "TestOsIncompatible"
            "TestArchOsIncompatible"
        )
        ##print_shellcode_tree( test3 ) # For updating the test...
        ##sys.exit(0)                   # For updating the test...
        from StringIO import StringIO
        stdout = sys.stdout
        capture = StringIO()
        try:
            sys.stdout = capture
            print_shellcode_tree( test3 )
        finally:
            sys.stdout = stdout
        assert capture.getvalue() == (
"""Concatenator
* Platform:  any (any)
* Provides:  multiarch, multios
* Children:  2
* Length:    112
* Bytes:     5465737441726368...6d70617469626c65

    Concatenator
    * Platform:  windows (x86)
    * Provides:  multiarch, multios
    * Encoding:  nullfree
    * Children:  3
    * Length:    52
    * Bytes:     5465737441726368...6f6d657468696e67

        Concatenator
        * Platform:  windows (x86)
        * Provides:  multiarch, multios
        * Encoding:  nullfree, unicode
        * Children:  2
        * Length:    20
        * Bytes:     5465737441726368...6573744f73416e79

            TestArchAny
            * Platform:  windows (any)
            * Provides:  multiarch
            * Encoding:  nullfree, unicode
            * Length:    11
            * Bytes:     5465737441726368416e79

            TestOsAny
            * Platform:  any (x86)
            * Provides:  multios
            * Encoding:  nullfree, unicode
            * Length:    9
            * Bytes:     546573744f73416e79

        TestArchOsAny
        * Platform:  any (any)
        * Provides:  multiarch, multios
        * Encoding:  nullfree
        * Length:    13
        * Bytes:     54657374417263684f73416e79

        TestArchOsSomething
        * Platform:  windows (x86)
        * Encoding:  ascii, nullfree
        * Length:    19
        * Bytes:     5465737441726368...6f6d657468696e67

    Concatenator
    * Platform:  osx (ppc)
    * Provides:  multiarch, multios
    * Children:  3
    * Length:    60
    * Bytes:     5465737441726368...6d70617469626c65

        TestArchIncompatible
        * Platform:  any (ppc)
        * Provides:  multios
        * Encoding:  nullfree
        * Length:    20
        * Bytes:     5465737441726368...6d70617469626c65

        TestOsIncompatible
        * Platform:  osx (any)
        * Provides:  multiarch
        * Length:    18
        * Bytes:     546573744f73496e...6d70617469626c65

        TestArchOsIncompatible
        * Platform:  osx (ppc)
        * Encoding:  nullfree
        * Length:    22
        * Bytes:     5465737441726368...6d70617469626c65

""")

        # Test the dynamic shellcode's cache.
        import random
        class TestBytecodeCache(Dynamic):
            def compile(self, state):
                return random_chars( random.randint(1, 16) )
        test_rnd = TestBytecodeCache()
        assert test_rnd.bytes == test_rnd.bytes
        tmp = test_rnd.bytes
        test_rnd.compile()
        assert tmp != test_rnd.bytes
        test_rnd1 = TestBytecodeCache()
        test_rnd2 = TestBytecodeCache()
        test_rnd3 = TestBytecodeCache()
        test_rnd = test_rnd1 + test_rnd2 + test_rnd3
        assert test_rnd.bytes == test_rnd.bytes
        assert test_rnd1.bytes == test_rnd1.bytes
        assert test_rnd2.bytes == test_rnd2.bytes
        assert test_rnd3.bytes == test_rnd3.bytes
        tmp = test_rnd.bytes
        tmp1 = test_rnd1.bytes
        tmp2 = test_rnd2.bytes
        tmp3 = test_rnd3.bytes
        test_rnd.compile()
        assert tmp != test_rnd.bytes
        assert tmp1 != test_rnd1.bytes
        assert tmp2 != test_rnd2.bytes
        assert tmp3 != test_rnd3.bytes

        # Test loading shellcode modules dynamically.
        MyNop = get_shellcode_class("x86", "any", "nop", "Nop")
        from shellgen.x86.nop import Nop
        assert MyNop is Nop
        assert Nop.arch == "x86"
        assert Nop.os == "any"
        MyPadder = get_shellcode_class("x86_64", None, "nop", "Padder")
        from shellgen.x86_64.nop import Padder
        assert MyPadder is Padder
        assert Padder.arch == "x86_64"
        assert Padder.os == "any"
        MyExecute = get_shellcode_class("mips", "irix", "execute", "Execute")
        from shellgen.mips.irix.execute import Execute
        assert MyExecute is Execute
        assert Execute.arch == "mips"
        assert Execute.os == "irix"
        try:
            get_shellcode_class("fake", "fake", "fake", "Fake")
            assert False
        except NotImplementedError:
            pass
        except Exception:
            assert False
        try:
            get_shellcode_class(".fake", "fake", "fake", "Fake")
            assert False
        except ValueError:
            pass
        except Exception:
            assert False
        try:
            get_shellcode_class("fake", "/fake", "fake", "Fake")
            assert False
        except ValueError:
            pass
        except Exception:
            assert False
        try:
            get_shellcode_class("fake", "fake", ".fake", "Fake")
            assert False
        except ValueError:
            pass
        except Exception:
            assert False
        try:
            get_shellcode_class("fake", "fake", "fake", "Fa.ke")
            assert False
        except ValueError:
            pass
        except Exception:
            assert False
        try:
            get_shellcode_class("\\fake", "fake", "fake", "Fake")
            assert False
        except ValueError:
            pass
        except Exception:
            assert False
        try:
            get_shellcode_class("fake", "*fake", "fake", "Fake")
            assert False
        except ValueError:
            pass
        except Exception:
            assert False
        try:
            get_shellcode_class("fake", "fake", "fake", "_Fake")
            assert False
        except ValueError:
            pass
        except Exception:
            assert False

        # Test listing the available platforms.
        platforms = get_available_platforms()
        ##print platforms
        assert platforms
        assert len(set(platforms)) == len(platforms)
        assert sorted(platforms) == platforms
        assert all((len(x) == 2 for x in platforms))
        assert all((x[0].lower().strip() == x[0] and x[1].lower().strip() == x[1] \
                    for x in platforms))

        # Test character generation.
        assert len(set(default_bad_chars)) == len(default_bad_chars)
        assert len(set(good_chars())) == len(good_chars())
        assert len(default_bad_chars) + len(good_chars()) == 256
        assert set(good_chars()).isdisjoint(set(default_bad_chars))
        assert set(random_chars(100)).isdisjoint(set(default_bad_chars))

        # Test encoding autodetection.
        try:
            autodetect_encoding(1)
            assert False
        except TypeError:
            pass
        try:
            Raw(1)
            assert False
        except TypeError:
            pass
        empty_str_encoding = autodetect_encoding("")
        assert empty_str_encoding == autodetect_encoding(None)
        assert empty_str_encoding == Raw("").encoding
        assert empty_str_encoding == Raw(Raw("")).encoding
        assert empty_str_encoding == autodetect_encoding(Raw(""))
        assert "nullfree" in autodetect_encoding(random_chars(100))
        assert "nullfree" in Raw(random_chars(100)).encoding
        encoding_test_data = {
            "": ('alpha', 'ascii', 'lower', 'nullfree', 'unicode', 'upper'),
            "\x00": ('alpha', 'ascii', 'lower', 'term_null', 'upper'),
            "\x00\x00": ('alpha', 'ascii', 'lower', 'unicode', 'upper'),
            "hola manola\x00": ('ascii', 'lower', 'term_null'),
            "HOLA MANOLA\x00": ('ascii', 'term_null', 'upper'),
            "Hola Manola": ('ascii', 'nullfree'),
            "matanga\x00": ('alpha', 'ascii', 'lower', 'term_null'),
            "MATANGA\x00": ('alpha', 'ascii', 'term_null', 'upper'),
            "Matanga": ('alpha', 'ascii', 'nullfree'),
            "h\0o\0l\0a\0 \0m\0a\0n\0o\0l\0a\0": ('ascii', 'lower', 'unicode'),
            "h\0o\0l\0a\0 \0m\0a\0n\0o\0l\0a\0\0": ('ascii', 'lower'),              # unaligned size
            "\0h\0o\0l\0a\0 \0m\0a\0n\0o\0l\0a\0\0": ('ascii', 'lower'),            # unaligned address
            "h\0o\0l\0a\0 \0m\0a\0n\0o\0l\0a\0\0\0": ('ascii', 'lower', 'term_null', 'unicode'),
            "M\0A\0T\0A\0N\0G\0A\0": ('alpha', 'ascii', 'unicode', 'upper'),
            "M\0A\0T\0A\0N\0G\0A\0\0": ('alpha', 'ascii', 'upper'),                 # unaligned size
            "\0M\0A\0T\0A\0N\0G\0A\0": ('alpha', 'ascii', 'upper'),                 # unaligned address
            "M\0A\0T\0A\0N\0G\0A\0\0\0": ('alpha', 'ascii', 'term_null', 'unicode', 'upper'),
            "Matanga!": ('ascii', 'nullfree'),
            chr(128): ('lower', 'nullfree', 'upper'),
            (chr(128) + chr(0)): ('lower', 'term_null', 'unicode', 'upper'),
            (chr(128) + chr(128) + chr(0)): ('lower', 'term_null', 'upper'),
            (chr(128) + chr(0) + chr(128)): ('lower', 'upper'),
            default_bad_chars: ('ascii', 'lower', 'upper'),
            good_chars(): ('nullfree',),
        }
        for test_str, test_result in encoding_test_data.iteritems():
            if autodetect_encoding(test_str) != test_result:
                raise AssertionError("autodetect_encoding() test failed: %r" % test_str)
            if Raw(test_str).encoding != test_result:
                raise AssertionError("Raw() test failed: %r" % test_str)

    test()
