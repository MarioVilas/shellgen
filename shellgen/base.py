#!/usr/bin/env python

###############################################################################
## Core features of ShellGen                                                 ##
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

"Core features of ShellGen."

import sys
import keyword
import weakref
import warnings
import functools

from os import path

__all__ = [

    # Public symbols. Seen by the user.
    'ShellcodeWarning', 'CompileError', 'EncodingError',
    'CompilerState',
    'Shellcode', 'Dynamic', 'Static', 'Raw',
    'Container', 'Concatenator', 'Decorator', 'Encoder', 'Stager',

    # Private symbols. Seen by the shellcode developer.
    'base_dir', 'base_package', 'base_file',
    'is_valid_module_path_component', 'meta_canonicalize_platform_tag',
    'meta_canonicalize_platform', 'meta_canonicalize_tags',
    'meta_canonicalize', 'meta_autodetect_platform',
    'meta_autodetect_encoding', 'meta_compile', 'meta_shellcode',
    'meta_shellcode_final', 'meta_shellcode_static', 'meta_shellcode_raw',
    'copy_classes',
]

# Get the path in the filesystem where this library is installed.
base_dir = path.abspath(path.dirname(__file__))

# When importing, get our package and module name.
# Fail if this file's been moved elsewhere.
try:
    base_package, base_file = __name__.split('.')[-2:]
except Exception:
    msg = "Trying to load %s outside of its package" % __file__
    raise ImportError(msg)

#-----------------------------------------------------------------------------#

# This method may be a little paranoid, but better safe than sorry!
def is_valid_module_path_component(token):
    "Validate strings to be used when importing modules dynamically."
    return not token.startswith('_') and not keyword.iskeyword(token) and \
        all( ( (x.isalnum() or x == '_') for x in token ) )

def meta_canonicalize_platform_tag(tag):
    "Canonicalizes the processor architecture. See L{meta_canonicalize}."
    if not tag:
        tag = 'any'
    else:
        tag = tag.strip().lower()
    return tag

def meta_canonicalize_platform(arch, os, classname = None):
    "Canonicalizes and validates arch and os. See L{meta_canonicalize}."

    # Validate the processor architecture.
    if not isinstance(arch, property):
        arch = meta_canonicalize_platform_tag(arch)
        if not is_valid_module_path_component(arch):
            if classname:
                msg = "Bad processor architecture in %s: %r"
                msg = msg % (classname, arch)
            else:
                msg = "Bad processor architecture: %r"
                msg = msg % arch
            raise ValueError(msg)

    # Validate the operating system.
    if not isinstance(os, property):
        os = meta_canonicalize_platform_tag(os)
        if not is_valid_module_path_component(os):
            if classname:
                msg = "Bad operating system in %s: %r"
                msg = msg % (classname, os)
            else:
                msg = "Bad operating system: %r"
                msg = msg % os
            raise ValueError(msg)

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
        if ',' in tags:
            tags = tuple(tags.split(','))
        elif ' ' in tags or '\t' in tags:
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
    cls.arch, cls.os = meta_canonicalize_platform(cls.arch, cls.os, clsname)

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
    if module != '__main__':
        tokens = cls.__module__.split('.')
        if len(tokens) < 2 or tokens[0] != base_package or \
                              tokens[1] == base_file:
            return
        tokens.insert(-1, 'any')
        tokens = tokens[1:3]
    else:
        module = abspath(sys.modules[module].__file__)
        if not module.startswith(base_dir):
            return
        tokens = module.split(sep)
        tokens = tokens[len(base_dir.split(sep)):-1]
        while len(tokens) < 2:
            tokens.append('any')
    cls.arch, cls.os = tokens

def meta_autodetect_encoding(bytes):
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
        bytes = ''
    if '\x00' not in bytes:
        encoding.append('nullfree')
    elif bytes.endswith('\x00') and '\x00' not in bytes[:-1]:
        encoding.append('term_null')
    try:
        if bytes == bytes.encode('ascii'):
            encoding.append('ascii')
            if all( ((x == '\x00' or x.isalnum()) for x in bytes) ):
                encoding.append('alpha')
    except Exception:
        pass
    if bytes == bytes.lower():
        encoding.append('lower')
    if bytes == bytes.upper():
        encoding.append('upper')
    if len(bytes) & 1 == 0:
        if all( ( bytes[i] == '\x00' for i in xrange(1, len(bytes), 2) ) ):
            encoding.append('unicode')
            if bytes.endswith('\x00\x00') and not all(
                (bytes[i] == '\x00' for i in xrange(0, len(bytes), 2) ) ):
                    encoding.append('term_null')
    return tuple(sorted(encoding))

def meta_compile(compile):
    "Wraps the compile() method to do dark magic, see L{meta_shellcode}."

    @functools.wraps(compile)
    def compile_wrapper(self, state = None):
        if state is None:
            state = CompilerState()
        self.offset = state.offset
        if hasattr(self, '_compile_hook'):
            bytes = self._compile_hook(compile, state)
        else:
            bytes = compile(self, state)
        state.next_piece( len(bytes) )
        return bytes

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
                        getattr(b, 'compile', None) for b in cls.__bases__):
                cls.compile = meta_compile(cls.compile)
            ##elif cls.__name__ not in ('Raw', 'Container'):
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
    "Same as L{meta_shellcode} but specifically for static shellcodes."
    def __init__(cls, name, bases, namespace):
        super(meta_shellcode_static, cls).__init__(name, bases, namespace)

        # Make sure the user wasn't so crazy to have compile() in a Static.
        if cls.__module__ != __name__ and cls.compile not in (
                    getattr(b, 'compile', None) for b in cls.__bases__):
            msg = (
                "What's %s.compile doing there?"
                " Are you nuts?!"
                " *Slap in the wrist*"
            ) % cls.__name__
            raise TypeError(msg)

        # Autodetect encoding if missing or empty.
        if not cls.encoding and not isinstance(cls.bytes, property):
            cls.encoding = meta_autodetect_encoding(cls.bytes)

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

#-----------------------------------------------------------------------------#

class ShellcodeWarning (RuntimeWarning):
    "Warnings issued by this library are of this type."

class ShellcodeError (RuntimeError):
    "An error occurred when preparing the shellcode."

    def __init__(self, message = None, clazz = None):

        # Error message defaults to docstring for this exception class.
        if not message:
            message = self.__doc__

        # If given, prepend the calling class name to the message.
        if clazz is not None:
            message = '%s: %s' % (clazz.__name__, message)

        # Give the error message to the parent constructor.
        RuntimeError.__init__(self, message)

class CompileError (ShellcodeError):
    "An error occurred when compiling the shellcode."

class EncodingError (CompileError):
    "A compile error occurred when trying to meet the encoding requirements."

#-----------------------------------------------------------------------------#

class CompilerState (object):
    """
    Compiler state variables.

    They are passed to and modified in place by all pieces of shellcode
    during compilation, in left to right order.

    @type offset: int
    @ivar offset: Current offset in the compiled bytecode.

    @type  current: dict
    @param current: Current state.
        This is used by this piece of shellcode to communicate things to
        the next piece, but only to the next piece.

    @type  previous: dict
    @param previous: Previous state.
        This is used by the previous piece of shellcode to communicate things
        to this piece, but only to this piece.

    @type shared: dict
    @ivar shared: Shared variables.
        This is used to communicate things to all pieces of the shellcode.

    @type callback: WeakValueDictionary
    @ivar callback: Callback functions.
        This is used to communicate things to all pieces of the shellcode.
    """
    def __init__(self):
        self.reset()

    def reset(self):
        "Reset the state."
        self.offset   = 0
        self.current  = {}
        self.previous = {}
        self.shared   = {}
        self.callback = weakref.WeakValueDictionary()

    def next_piece(self, delta = 0):
        """
        Called when moving to the next piece of shellcode.

        @type  delta: int
        @param delta: Number of compiled bytes in this piece of shellcode.
            It will be added to L{position}.
        """
        self.offset   += delta
        self.previous  = self.current
        self.current   = {}

    def register_callback(self, name, function):
        """
        Register a callback function.

        @note: Callbacks are stored as weak references.

        @see: L{call}, L{unregister_callback}

        @type  name: str
        @param name: Name of the callback function.

        @type  function: callable
        @param function: Callback function. when called the first argument it
            receives will be this CompilerState object.
        """
        self.callback[name] = function

    def unregister_callback(self, name):
        """
        Unregister a callback function.

        @note: Does not raise any exception when the callback had already been
            unregistered, or was never registered in the first place.

        @see: L{call}, L{register_callback}

        @type  name: str
        @param name: Name of the callback function.
        """
        try:
            del self.callback[name]
        except KeyError:
            pass

    def call(self, name, *argv, **argd):
        """
        Call a registered callback function, passing it this CompilerState
        object as the first argument, followed by all extra arguments passed to
        this method.

        @see: L{register_callback}, L{unregister_callback}

        @type  name: str
        @param name: Name of the callback function.

        @return: Return value of the callback function.
        @raise KeyError: The callback is not registered.
            Since callbacks are stored as weak references, they may be
            unregistered automatically when the object they live in is
            destroyed.
        """
        try:
            function = self.callback[name]
        except KeyError:
            msg = ("Callback %r is not registered."
                   " Maybe the shellcode that registered it is gone?")
            raise KeyError(msg % name)
        return function(self, *argv, **argd)

    # XXX not sure if this should be here, it's practical but not very elegant
    def requires_nullfree(self):
        """
        @rtype:  bool
        @return: C{True} if the shellcode is required to be null free,
            C{False} otherwise.
        """
        return (
            'nullfree' in self.shared.get('encoding', '') or
            '\x00' in self.shared.get('badchars', '')
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

    @type offset: int
    @ivar offset: Current offset assumed when compiling.
        Filled in automatically during compilation.

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
    arch      = 'any'
    os        = 'any'
    requires  = ()
    provides  = ()
    qualities = ()
    encoding  = ()

    # TO DO: helper functions to check dependencies and constraints

    # Default to offset 0.
    offset = 0

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

    def is_compiled(self):
        """
        Determines if the shellcode has been compiled.

        A shellcode is compiled after the L{compile} method is called, and it's
        not compiled when it hasn't been called yet or after the L{clean}
        method is called.

        For example::
            >>> from shellgen.x86.nop import Nop
            >>> shellcode = Nop()
            >>> shellcode.is_compiled()
            False
            >>> shellcode.compile()
            >>> shellcode.is_compiled()
            True
            >>> shellcode.clean()
            >>> shellcode.is_compiled()
            False
            >>> shellcode.bytes     # implicit call to shellcode.compile()
            '\x90'
            >>> shellcode.is_compiled()
            True

        @rtype:  bool
        @return: C{True} if the shellcode is compiled, C{False} otherwise.
        """
        raise NotImplementedError("Subclasses MUST implement this method!")

    def clean(self):
        "Clean the compilation of this shellcode."
        pass

    def relocate(self, delta):
        """
        Relocate bytecode by the specified delta offset if possible.

        The L{offset} instance variable will be incremented by C{delta}.

        @note: Note to shellcode writers:

            Most shellcodes can safely ignore this, since they're position
            independent anyways.

            However, if your shellcode somehow depends on the relative position
            of other pieces of shellcode, then you need to either update the
            bytecode or raise an exception if it's not possible to update it.

            Also, if you implement this method, don't forget to call the
            superclass method!

        @type  delta: int
        @param delta: Delta offset.

        @raise NotImplementedError: This shellcode doesn't support relocation.
        @raise RuntimeError: An error occurred when trying to relocate.
        """
        #
        # XXX TODO
        #
        # Some serious rethinking is needed for this feature, I fear it'll be
        # insufficient and cumbersome as it is now. Ideally relocations should
        # be dealt with in a fully automated way whenever possible!
        #
        # Maybe a relocation table could be implemented, and function calls
        # across shellcodes would automatically populate it. It'd be tricky,
        # but doable, and it'd save shellcode writers from dealing with this.
        #
        # I'm also not convinced with the API for this, but there must be a
        # relocate() method anyway, because some weird shellcodes may need to
        # do manual relocations instead of using the relocation table.
        #
        if delta != 0:
            self.offset += delta
            unchanged = True
            for child in self.children:
                if not child.is_compiled():
                    unchanged = False
                if unchanged:
                    bytes = child.bytes
                child.relocate(delta)
                if unchanged and bytes != child.bytes:
                    unchanged = False
            if not unchanged and self.is_compiled():
                offset = self.offset
                try:
                    self.clean()
                finally:
                    self.offset = offset

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
        if 'any' not in (self.arch, other.arch) and self.arch != other.arch:
            msg = "Processor architectures don't match: %s and %s"
            msg = msg % (self.arch, other.arch)
            warnings.warn(msg, ShellcodeWarning)
        if 'any' not in (self.os, other.os) and self.os != other.os:
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

    def add_provision(self, provision):
        """
        Add the given provided feature on runtime.

        @see: L{provides}

        @type  provision: str
        @param provision: Feature.
        """
        provides = meta_canonicalize_tags(provision)
        provides = meta_canonicalize_tags(self.provides + provides)
        self.provides = provides

    def remove_provision(self, provision):
        """
        Remove the given provided feature on runtime.

        @see: L{provides}

        @type  provision: str
        @param provision: Feature.
        """
        tmp = list(self.provides)
        for x in meta_canonicalize_tags(provision):
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
    bytes = ''

    def compile(self, state = None):
        return self.bytes

    def is_compiled(self):
        return True

#-----------------------------------------------------------------------------#

class Raw (Static):
    """
    Static shellcode that comes from raw bytes provided by the user.

    It's an easy way to build custom shellcodes without having to think. :)

    Used automatically when concatenating strings to shellcodes.
    """

    # Don't subclass this class. Also don't add a compile() method.
    __metaclass__= meta_shellcode_raw

    def __init__(self, bytes, arch = 'any', os = 'any',
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
            Autodetected by default, see: L{util.autodetect_encoding}.
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
            self.encoding = meta_autodetect_encoding(bytes)

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
        if self.is_compiled():
            return self.__bytes

        # Compile the shellcode.
        self.compile()

        # If compilation fails, raise an exception.
        if not self.is_compiled():
            msg = (
                "Compilation failed. Did you forget"
                " to return the bytecode at %s.compile?"
            ) % self.__class__.__name__
            raise RuntimeError(msg)

        # Return the compiled bytes.
        return self.__bytes

    def is_compiled(self):

        # It's compiled if the cache is not empty.
        return self.__bytes is not None

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

    @note: By default, the encoding of a Container instance is the intersection
        if the encoding declared in the class with the encodings of its child
        instances. For example::

            >>> import shellgen
            >>> class ExampleShellcode (shellgen.Static):
            ...     encoding = ('unicode', 'nullfree')
            ...
            >>> class ExampleContainer (shellgen.Container):
            ...     encoding = ('ascii', 'nullfree')
            ...
            >>> print ExampleContainer( ExampleShellcode() ).encoding
            ('nullfree',)

        If the Container class doesn't declare any encoding, then only the
        children's encodings are intersected::

            >>> import shellgen
            >>> class ExampleShellcode (shellgen.Static):
            ...     encoding = ('ascii', 'nullfree')
            ...
            >>> class ExampleContainer (shellgen.Container):
            ...     pass
            ...
            >>> print ExampleContainer( ExampleShellcode() ).encoding
            ('ascii', 'nullfree')

        To override this behavior, you can set the metadata in the constructor
        of your subclass, for example like this::

            class ExampleContainer (shellgen.Container):

                # Encoding declared in the class describes the code added by
                # the container itself, independently of the children.
                encoding = ('ascii', 'nullfree')

                def __init__(self, *children):
                    super(ExampleContainer, self).__init__(*children)

                    # This forces instances to use the encoding of the class.
                    self.encoding = ExampleContainer.encoding
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

    # Dark magic to implement the metadata combination feature.
    def __getattribute__(self, name):

        # Get the super getattribute method.
        # Using it prevents an infinite recursion.
        getattribute = super(Container, self).__getattribute__

        # The dark magic is only for the "encoding" property.
        # Use the normal lookup mechanism for everything else.
        if name != 'encoding':
            return getattribute(name)

        # Get the dictionary of instance variables.
        # This excludes the variables defined in the class.
        instance_vars = object.__getattribute__(self, '__dict__')

        # If the value is defined as an instance variable,
        # return it unmodified.
        try:
            return instance_vars[name]

        # If it's a class variable, do the dark magic...
        except KeyError:

            # Get the value using the normal lookup.
            # This works for both class variables and property methods.
            try:
                value = getattribute(name)
            except AttributeError:
                value = None

            # If the value was obtained through a property method,
            # return it unmodified.
            clazz = getattribute('__class__')
            property_type = type(getattr(clazz, name, None))
            if issubclass(property_type, property):
                return value

            # When the Container subclass defines its own encoding,
            # the class encoding is intersected with that of the children.
            # This works because we have a property method in the base class,
            # so we only reach this point if the subclass redefines it.
            encoding = set( meta_canonicalize_tags(value) )
            if encoding:
                intersect = encoding.intersection_update
                for child in getattribute('children'):
                    intersect( meta_canonicalize_tags(child.encoding) )
                    if not encoding:
                        break

            # Canonicalize the intersected encodings.
            value = meta_canonicalize_tags(encoding)

        # Return the calculated value.
        return value

    # Returns the intersection of all encodings, ignoring our own.
    # This method gets overridden if the subclass defines its own "encoding".
    # Also see the code of __getattribute__().
    @property
    def encoding(self):
        encoding = set()
        update = encoding.update
        intersect = encoding.intersection_update
        for child in self.children:
            update(child.encoding)
            if not encoding:
                break
            update = intersect
        return meta_canonicalize_tags(encoding)

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
        bytes = ''
        for child in self.children:
            bytes += child.compile(state)
        return bytes

#-----------------------------------------------------------------------------#

class Concatenator (Container):
    """
    Simple concatenation of two or more shellcodes.

    @type arch: str
    @ivar arch: Processor architecture common to all child shellcodes.
        If there is no common architecture, the value will be "any".

    @type os: str
    @ivar os: Operating system common to all child shellcodes.
        If there is no common OS, the value will be "any".

    @type encoding: tuple(str)
    @ivar encoding: Intersection of the supported encodings of all its child
        shellcodes.
    """

    # Don't subclass this class.
    __metaclass__= meta_shellcode_final

    # Disable the metadata dark magic, property methods are faster.
    __getattribute__ = object.__getattribute__

    def __init__(self, *children):

        # Populate the list of children.
        super(Concatenator, self).__init__(*children)

    # If all children are compatible with the same architecture, return it.
    # Otherwise return "any".
    @property
    def arch(self):
        arch = 'any'
        for child in self.children:
            if child.arch != 'any':
                if arch == 'any':
                    arch = child.arch
                elif child.arch != arch:
                    arch = 'any'
                    break
        return arch

    # If all children are compatible with the same OS, return it.
    # Otherwise return "any".
    @property
    def os(self):
        os = 'any'
        for child in self.children:
            if child.os != 'any':
                if os == 'any':
                    os = child.os
                elif child.os != os:
                    os = 'any'
                    break
        return os

    # Returns the intersection of all encodings.
    @property
    def encoding(self):
        encoding = set()
        update = encoding.update
        intersect = encoding.intersection_update
        for child in self.children:
            update(child.encoding)
            if not encoding:
                break
            update = intersect
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
    Encoders wrap around a shellcode to pass encoding restrictions, for example
    ASCII character filters or Unicode codepage conversions.

    @note: Encoders always override the encoding of their child.

        For example::

            >>> import shellgen
            >>> class ExampleShellcode (shellgen.Static):
            ...     encoding = ('term_null',)
            ...
            >>> class ExampleEncoder (shellgen.Encoder):
            ...     encoding = ('alpha', 'nullfree')
            ...
            >>> print ExampleShellcode().encoding
            ('term_null',)
            >>> print ExampleEncoder( ExampleShellcode() ).encoding
            ('alpha', 'nullfree')
    """

    # Encoder instances don't inherit the encoding of the child.
    __getattribute__ = object.__getattribute__
    encoding = ()

    def compile(self, state):
        raise NotImplementedError(
            "Encoders MUST implement the compile() method!")

#-----------------------------------------------------------------------------#

class Stager (Dynamic):
    """
    Stagers split shellcode execution into load stages.

    @type next_stage: L{Shellcode}
    @ivar next_stage: Next load stage.
    """

    # Updated on object instances.
    _next_stage = None

    def __init__(self, next_stage):
        """
        @type  next_stage: L{Shellcode}
        @param next_stage: Next load stage.
        """
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

#class Callable(Decorator):
#    """
#    Callable shellcodes define functions that can be called from other pieces
#    of shellcode.
#
#    The child shellcode and the calling shellcodes must support relocation.
#
#    @see: L{relocate}
#
#    @type name: str
#    @ivar name: Name of the function.
#
#    @type offset: int
#    @ivar offset: Offset from the start of the complete shellcode where the
#        function is assumed to be. This property is set automatically when
#        compiling. See: L{CompilerState.offset}
#    """
#
#    def __init__(self, child, name):
#        """
#        @type  child: L{Shellcode}
#        @param child: Shellcode to be made into a function.
#
#        @type  name: str
#        @param name: Name of the function.
#            When compiling, a shared variable of this name will be stored in
#            the L{CompilerState}. Calling shellcodes can call the function
#            like this::
#
#                def compile(self, state):
#                    bytes = ''
#
#                    # ...stuff...
#
#                    # Adds a call/branch instruction to the bytecode, that will
#                    # execute the code of the 'example' shellcode and return.
#                    bytes = state.call('example', bytes)
#
#                    # ...stuff...
#
#                    return bytes
#        """
#        super(Callable, self).__init__(child)
#        self.name = name
#        self.offset = 0
#
#    # Do not implement compile(), use make_function() instead.
#    def compile(self, state):
#        self.offset = state.offset
#        child = self.child
#        child.compile(state)
#        bytes = self.make_function(state, child)
#        state.register_callback(self.name, self.make_function_call)
#        return bytes
#
#    def clean(self):
#        super(Callable, self).clean()
#        self.offset = 0
#
#    def make_function(self, state, child):
#        """
#        Turn a compiled child shellcode into a function.
#
#        Tipically this will be done by inserting an unconditional branch
#        before the child code to skip it, and a return instruction at the end.
#        """
#        raise NotImplementedError("Subclasses MUST implement this method!")
#
#    def make_function_call(self, state, bytes):
#        """
#        Compile a call/branch instruction pointing to the child shellcode.
#
#        @type  state: L{CompilerState}
#        @param state: Compilation variables.
#
#        @type  bytes: str
#        @param bytes: Bytecode currently being compiled.
#
#        @rtype:  str
#        @return: Bytecode currently being compiled, with the addition of a
#            call/branch instruction pointing to the child shellcode.
#        """
#        raise NotImplementedError("Subclasses MUST implement this method!")

#-----------------------------------------------------------------------------#

#class Resolver(Dynamic):
#    """
#    Resolver shellcodes allow access to functions in dynamic libraries.
#
#    This is required by some platforms like Windows, where issuing direct
#    syscalls is not recommended.
#    """

#-----------------------------------------------------------------------------#

def test():
    "Unit test."

    # Static subclasses shouldn't define their own compile() method.
    # However this check is disabled for base.py only.
    # This test verifies that.
    class TestStaticCompile (Static):
        bytes == 'matanga'
        def compile(self, state):
            return 'hola manola'
    assert TestStaticCompile().compile() == 'hola manola'

    # Raw shouldn't be subclassed.
    try:
        class TestSubclassedRaw (Raw):
            pass
        #print "meta_shellcode_raw() verification failed!"
        assert False
    except TypeError:
        ##raise
        pass

    # Concatenator shouldn't be subclassed.
    try:
        class TestSubclassedConcatenator (Concatenator):
            pass
        #print "meta_shellcode_final() verification failed!"
        assert False
    except TypeError:
        ##raise
        pass

    # Test the canonicalization of the metadata in a class.
    class TestCanonicalization(Static):
        requires = 'requires'
        provides = ['   pro', 'VideS', 'PRO   ']
        qualities = '  quali, ties  '
        encoding = (x for x in ('en', 'co', 'ding'))
        bytes = ''
    assert TestCanonicalization.requires  == ('requires',)
    assert TestCanonicalization.provides  == ('pro', 'vides')
    assert TestCanonicalization.qualities == ('quali', 'ties')
    assert TestCanonicalization.encoding  == ('co', 'ding', 'en')

    # Test editing the metadata in an instance.
    t = TestCanonicalization()
    t.add_requirement('re')
    t.remove_requirement('fake')
    t.remove_requirement('requires')
    t.add_requirement('quires')
    assert t.requires == ('quires', 're')
    assert t.requires != TestCanonicalization.requires
    t.remove_provision('fake')
    t.add_provision(' PRO VIDES ')
    t.add_provision('\tPRO\tVIDES\t')
    t.add_provision('PrO, VideS')
    assert t.provides == TestCanonicalization.provides
    t.remove_provision('pro')
    t.add_provision('Feature')
    assert t.provides == ('feature', 'vides')
    assert t.provides != TestCanonicalization.provides
    t.add_quality('ti')
    t.remove_quality('fake')
    t.add_quality('es')
    t.remove_quality('ties')
    assert t.qualities == ('es', 'quali', 'ti')
    assert t.qualities != TestCanonicalization.qualities
    t.add_encoding('EN')
    t.add_encoding('  co  ')
    t.add_encoding('\tDiNg\t')
    t.add_encoding(' enco  di  ')
    t.add_encoding(' n, g ')
    assert t.encoding == ('co', 'di', 'ding', 'en', 'enco', 'g', 'n')
    assert t.encoding != TestCanonicalization.encoding

    # Test encoding inheritance for Container shellcodes.
    class ExampleShellcode (Static):
        encoding = ('unicode', 'nullfree')
    class ExampleContainer (Container):
        encoding = ('ascii', 'nullfree')
    assert ExampleContainer( ExampleShellcode() ).encoding == ('nullfree',)
    class ExampleContainer (Container):
        pass
    assert ExampleContainer( ExampleShellcode() ).encoding == \
                                 ExampleShellcode.encoding
    class ExampleContainer (Container):
        encoding = ('ascii', 'nullfree')
        def __init__(self, *children):
            super(ExampleContainer, self).__init__(*children)
            self.encoding = ExampleContainer.encoding
    assert ExampleContainer( ExampleShellcode() ).encoding == \
                                 ExampleContainer.encoding

    # Test encoding overriding for Encoder shellcodes.
    class ExampleShellcode (Static):
        encoding = ('term_null',)
    class ExampleEncoder (Encoder):
        encoding = ('nullfree',)
    assert ExampleShellcode().encoding == ('term_null',)
    assert ExampleEncoder( ExampleShellcode() ).encoding == ('nullfree',)

    # Test the platform metadata.
    class TestArchAny(Static):
        encoding = 'unicode, nullfree'
        bytes = 'TestArchAny'
    TestArchAny.arch = 'any'
    TestArchAny.os = 'windows'
    class TestOsAny(Static):
        encoding = 'unicode, nullfree'
        bytes = 'TestOsAny'
    TestOsAny.arch = 'x86'
    TestOsAny.os = 'any'
    class TestArchOsAny(Static):
        encoding = 'nullfree'
        bytes = 'TestArchOsAny'
    TestArchOsAny.arch = 'any'
    TestArchOsAny.os = 'any'
    class TestArchOsSomething(Static):
        encoding = 'ascii, nullfree'
        bytes = 'TestArchOsSomething'
    TestArchOsSomething.arch = 'x86'
    TestArchOsSomething.os = 'windows'
    class TestArchIncompatible(Static):
        encoding = 'nullfree'
        bytes = 'TestArchIncompatible'
    TestArchIncompatible.arch = 'ppc'
    TestArchIncompatible.os = 'any'
    class TestOsIncompatible(Static):
        encoding = 'ascii'
        bytes = 'TestOsIncompatible'
    TestOsIncompatible.arch = 'any'
    TestOsIncompatible.os = 'osx'
    class TestArchOsIncompatible(Static):
        encoding = 'nullfree'
        bytes = 'TestArchOsIncompatible'
    TestArchOsIncompatible.arch = 'ppc'
    TestArchOsIncompatible.os = 'osx'
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter('always')
        test1  = TestArchAny() + TestOsAny() + TestArchOsAny()
        test1 += TestArchOsSomething()
        test2  = TestArchIncompatible() + TestOsIncompatible()
        test2 += TestArchOsIncompatible()
        assert not w
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter('always')
        test3 = test1 + test2
        assert w
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter('always')
        TestArchAny() + TestOsIncompatible()
        assert w
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter('always')
        TestOsAny() + TestArchIncompatible()
        assert w
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter('always')
        TestArchOsSomething() + TestArchOsIncompatible()
        assert w

    # Test concatenation and encoding inheritance.
    # (This is a lame test, I know. I got lazy, sorry!)
    from shellgen.util import print_shellcode_tree
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
    expected = (
"""Concatenator
* Platform:  any (any)
* Children:  2

    Concatenator
    * Platform:  windows (x86)
    * Encoding:  nullfree
    * Children:  2

        Concatenator
        * Platform:  windows (x86)
        * Encoding:  nullfree
        * Children:  2

            Concatenator
            * Platform:  windows (x86)
            * Encoding:  nullfree, unicode
            * Children:  2

                TestArchAny
                * Platform:  windows (any)
                * Encoding:  nullfree, unicode
                * Length:    11
                * Bytes:     5465737441726368416e79

                TestOsAny
                * Platform:  any (x86)
                * Encoding:  nullfree, unicode
                * Length:    9
                * Bytes:     546573744f73416e79

            TestArchOsAny
            * Platform:  any (any)
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
    * Children:  2

        Concatenator
        * Platform:  osx (ppc)
        * Children:  2

            TestArchIncompatible
            * Platform:  any (ppc)
            * Encoding:  nullfree
            * Length:    20
            * Bytes:     5465737441726368...6d70617469626c65

            TestOsIncompatible
            * Platform:  osx (any)
            * Encoding:  ascii
            * Length:    18
            * Bytes:     546573744f73496e...6d70617469626c65

        TestArchOsIncompatible
        * Platform:  osx (ppc)
        * Encoding:  nullfree
        * Length:    22
        * Bytes:     5465737441726368...6d70617469626c65

""")
    ##open('1.txt','wb').write(capture.getvalue())  # for manually checking
    ##open('2.txt','wb').write(expected)            # the differences
    assert capture.getvalue() == expected
    test3.compile()
    assert test3.bytes == (
        'TestArchAny'
        'TestOsAny'
        'TestArchOsAny'
        'TestArchOsSomething'
        'TestArchIncompatible'
        'TestOsIncompatible'
        'TestArchOsIncompatible'
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
    expected = (
"""Concatenator
* Platform:  any (any)
* Children:  2
* Length:    112
* Bytes:     5465737441726368...6d70617469626c65

    Concatenator
    * Platform:  windows (x86)
    * Encoding:  nullfree
    * Children:  2
    * Length:    52
    * Bytes:     5465737441726368...6f6d657468696e67

        Concatenator
        * Platform:  windows (x86)
        * Encoding:  nullfree
        * Children:  2
        * Length:    33
        * Bytes:     5465737441726368...7263684f73416e79

            Concatenator
            * Platform:  windows (x86)
            * Encoding:  nullfree, unicode
            * Children:  2
            * Length:    20
            * Bytes:     5465737441726368...6573744f73416e79

                TestArchAny
                * Platform:  windows (any)
                * Encoding:  nullfree, unicode
                * Length:    11
                * Bytes:     5465737441726368416e79

                TestOsAny
                * Platform:  any (x86)
                * Encoding:  nullfree, unicode
                * Length:    9
                * Bytes:     546573744f73416e79

            TestArchOsAny
            * Platform:  any (any)
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
    * Children:  2
    * Length:    60
    * Bytes:     5465737441726368...6d70617469626c65

        Concatenator
        * Platform:  osx (ppc)
        * Children:  2
        * Length:    38
        * Bytes:     5465737441726368...6d70617469626c65

            TestArchIncompatible
            * Platform:  any (ppc)
            * Encoding:  nullfree
            * Length:    20
            * Bytes:     5465737441726368...6d70617469626c65

            TestOsIncompatible
            * Platform:  osx (any)
            * Encoding:  ascii
            * Length:    18
            * Bytes:     546573744f73496e...6d70617469626c65

        TestArchOsIncompatible
        * Platform:  osx (ppc)
        * Encoding:  nullfree
        * Length:    22
        * Bytes:     5465737441726368...6d70617469626c65

""")
    ##open('1.txt','wb').write(capture.getvalue())  # for manually checking
    ##open('2.txt','wb').write(expected)            # the differences
    assert capture.getvalue() == expected

    # Test warnings when concatenating more than once.
    test1 = TestArchOsAny()
    test2 = TestArchOsAny()
    test3 = test1 + test2
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter('always')
        test4 = test1 + test2
        assert w        # fails because test3 was the parent
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter('always')
        test3 += test2
        assert w        # fails because test4 was the parent
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter('always')
        del test3
        test4 = TestArchOsAny() + TestArchOsAny()
        test4 += test2
        assert not w    # now works because we deleted the parent

    # Test the dynamic shellcode's cache.
    import random
    class TestBytecodeCache(Dynamic):
        def compile(self, state):
            return ''.join((chr(random.randint(0, 255))
                            for x in xrange(random.randint(1, 16)) ))
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

    # Test stage inheritance.
    # XXX TODO
