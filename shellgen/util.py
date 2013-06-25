#!/usr/bin/env python

###############################################################################
## Utility functions for ShellGen                                            ##
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
Utility functions for ShellGen.

@type default_bad_chars: str
@var  default_bad_chars: Default list of bad characters for encoders.
"""

from __future__ import absolute_import
from .base import *

import re
import random
import struct
import warnings

from os import listdir, path

__all__ = [
    "bit_length", "compile_child",
    "get_shellcode_class", "get_available_platforms", "autodetect_encoding",
    "find_bad_chars", "default_bad_chars", "good_chars", "random_chars",
    "is_stack_balanced", #"uses_stack", "uses_heap", "uses_seh",
    "iter_shellcode", "find_shellcode", "print_shellcode_tree",
    "load_from_source",
]

#-----------------------------------------------------------------------------#

# Compatibility with Python 2.6 and earlier.
if hasattr(int, 'bit_length'):
    def bit_length(num):
        return num.bit_length()
else:
    import math
    def bit_length(num):
        return int(math.log(num, 2))

#-----------------------------------------------------------------------------#

def compile_child(shellcode, state = None,
                    current_offset = None,
                   preserve_offset = True,
                    preserve_state = True):
    """
    Compiles the given shellcode under special circumstances.

    Using the C{current_offset} option, compilation assumes the given offset
    instead of the value from L{CompilerState.offset}.

    Using the C{preserve_offset} option, the current offset is not modified
    after compiling the shellcode.

    Using the C{preserve_state} you can control whether the state reflects that
    another shellcode has been compiled, or it's treated as part as the
    currently compiling shellcode.

    @type  shellcode: L{Shellcode}
    @param shellcode: Shellcode to compile.

    @type  state: L{CompilerState}
    @param state: Compilation state.

    @type  current_offset: int
    @param current_offset: The current offset to use.

    @type  preserve_offset: bool
    @param preserve_offset: C{True} to preserve the offset, C{False} to update
        the offset after compilation.

    @type  preserve_state: bool
    @param preserve_state: C{True} to compile within the state context of the
        caller, C{False} to compile normally.

    @rtype:  str
    @return: Compiled bytecode.
    """
    if not state:
        state = CompilerState()
        if current_offset:
            state.offset = current_offset
    elif not current_offset:
        current_offset = state.offset
    old_offset  = state.offset
    old_current = state.current
    try:
        state.offset = current_offset
        if preserve_state:
            state.current = state.previous
        shellcode.compile(state)
    finally:
        if preserve_offset:
            state.offset  = old_offset
        if preserve_state:
            state.current = old_current
    return shellcode.bytes

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

    @see: L{get_available_platforms}

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
    arch, os = meta_canonicalize_platform(arch, os)

    # Abstract shellcodes can't be instanced.
    if arch == 'all':
        raise ValueError("Abstract shellcodes can't be instanced")

    # Validate the module and classname.
    if not is_valid_module_path_component(module):
        raise ValueError("Bad shellcode module: %r" % module)
    if not is_valid_module_path_component(classname):
        raise ValueError("Bad shellcode class: %r" % classname)

    # Build the fully qualified module name.
    if os == 'any':
        path = 'shellgen.%s.%s' % (arch, module)
    else:
        path = 'shellgen.%s.%s.%s' % (arch, os, module)

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

    @see: L{get_available_modules}, L{get_available_classes},
        L{get_shellcode_class}

    @rtype: list( tuple(str, str) )
    @return: List of available architectures from built-in shellcodes.
        Each element in the list is a tuple containing:
         - processor architecture
         - operating system
    """

    # A Python trick: keep some symbols external to the function as local vars.
    # This is faster because it avoids some name lookups in the loop below.
    isdir  = path.isdir
    isfile = path.isfile
    join   = path.join

    # This list will contain the platforms we find.
    platform_list = []

    # For each file and directory found in the install location...
    for arch_name in listdir(base_dir):

        # Skip hidden files, "." and "..", and private modules.
        if arch_name.startswith('.') or arch_name.startswith('_'):
            continue

        # Skip the "abstract" directory.
        if arch_name == 'abstract':
            continue

        # Skip non-directories and directories without "__init__.py" inside.
        arch_dir = join(base_dir, arch_name)
        if not isdir(arch_dir) or not isfile(join(arch_dir, '__init__.py')):
            continue

        # For each file and directory inside this directory...
        check_for_any = True
        for os_name in listdir(arch_dir):

            # Skip hidden files, "." and "..", and private modules.
            if os_name.startswith('.') or os_name.startswith('_'):
                continue

            # If it's a directory...
            os_dir = join(arch_dir, os_name)
            if isdir(os_dir):

                # If it has "__init__.py" inside...
                if isfile(join(os_dir, '__init__.py')):

                    # Add the architecture and OS tuple.
                    platform_list.append( (arch_name, os_name) )

            # If it's the first .py file we see...
            elif check_for_any and os_name.endswith('.py'):
                check_for_any = False

                # Add the architecture.
                platform_list.append( (arch_name, 'any') )

    # Sort the platforms.
    platform_list.sort()

    # Return the platforms.
    return platform_list

def get_available_modules(arch, os):
    """
    Get the list of available modules with built-in shellcodes.

    This operation involves accessing the filesystem, so you may want to cache
    the response.

    @see: L{get_available_platforms}

    @type  arch: str
    @param arch: Target processor architecture.
        Must be C{None} or C{"any"} for platform independent shellcodes.

    @type  os: str
    @param os: Target operating system.
        Must be C{None} or C{"any"} for OS independent shellcodes.

    @rtype:  list(str)
    @return: List of shellcode module names.
    @raise ValueError: Invalid arguments.
    """

    # Canonicalize the arch and os.
    arch, os = meta_canonicalize_platform(arch, os)

    # Build the path to the modules for that platform.
    if os == 'any':
        platform_path = path.join(base_dir, arch)
    else:
        platform_path = path.join(base_dir, arch, os)

    # If the directory doesn't exist, raise an exception.
    if not path.isdir(platform_path):
        if os == 'any':
            msg = "No built-in shellcodes available for the %r architecture."
            msg = msg % arch
        else:
            msg = "No built-in shellcodes available for the %s-%s platform."
            msg = msg % (os, arch)
        raise ValueError(msg)

    # Build the list of modules.
    module_list = [ x[:-3] for x in listdir(platform_path)
                      if not x.startswith('_') and x.endswith('.py')
                         and not x.startswith('_') ]

    # Sort the list of modules.
    module_list.sort()

    # Return the list of modules.
    return module_list

def get_available_classes(arch, os, module):
    """
    Get the list of available built-in shellcodes within the given module.

    This operation involves accessing the filesystem, so you may want to cache
    the response.

    @warn: This causes the module to be imported, in order to fetch the class
        names from it.

    @see: L{get_available_modules}

    @type  arch: str
    @param arch: Target processor architecture.
        Must be C{None} or C{"any"} for platform independent shellcodes.

    @type  os: str
    @param os: Target operating system.
        Must be C{None} or C{"any"} for OS independent shellcodes.

    @type  module: str
    @param module: Shellcode module name.

    @rtype:  list(class)
    @return: List of shellcode classes.
    """

    # Canonicalize the arch and os.
    arch, os = meta_canonicalize_platform(arch, os)

    # Validate the module.
    if not is_valid_module_path_component(module):
        raise ValueError("Bad shellcode module: %r" % module)

    # Build the fully qualified module name.
    if os == 'any':
        path = 'shellgen.%s.%s' % (arch, module)
    else:
        path = 'shellgen.%s.%s.%s' % (arch, os, module)

    # Load the module.
    try:
        modobj = __import__(path, fromlist = ['*'])
    except ImportError, e:
        msg = "Error loading module %s: %s" % (path, str(e))
        raise NotImplementedError(msg)

    # Return the classes that derive from Shellcode defined in this module.
    class_list = [getattr(modobj, name) for name in dir(modobj)]
    class_list = [clazz for clazz in class_list
                        if isinstance(clazz, type)      and
                           clazz.__module__ == path     and
                           issubclass(clazz, Shellcode) ]
    return class_list

#-----------------------------------------------------------------------------#

# Exported version of meta_autodetect_encoding().
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
    return meta_autodetect_encoding(bytes)

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
    return ''.join( (c for c in bad_chars if c in bytes) )

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
    return ''.join( (chr(c) for c in xrange(256) if c not in bad_list) )

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
    return ''.join( ( c[randint(0, m)] for i in xrange(length) ) )

#-----------------------------------------------------------------------------#

def is_stack_balanced(shellcode):
    """
    Determines if a given shellcode is stack balanced,
    by examining its metadata.

    @type  shellcode: L{Shellcode}
    @param shellcode: Any shellcode.

    @rtype:  bool
    @return: C{True} if the shellcode's metadata claims it's stack balanced,
        C{False otherwise}.
    """
    queue = [shellcode]
    while queue:
        shellcode = queue.pop()
        if isinstance(shellcode, Concatenator):
            queue.extend(shellcode.children)
            continue
        if 'stack_balanced' in shellcode.qualities:
            continue
        if 'no_stack' in shellcode.qualities:
            continue
        return False
    return True

#-----------------------------------------------------------------------------#

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
    elif hasattr(shellcode, '_Dynamic__bytes'): # For dynamic shellcodes,
        bytes = shellcode._Dynamic__bytes       #  get them from the cache.
        if bytes:
            length = len(bytes)
        else:
            length = 0
    if bytes is not None:
        if len(bytes) != length:
            warnings.warn("Bad length for %s" % shellcode.__class__.__name__)
        bytes = bytes.encode('hex')
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

def iter_shellcode(shellcode, clazz = Shellcode):
    """
    Iterate through all pieces of shellcode matching the given base class,
    in left to right order.

    @type  shellcode: L{Shellcode}
    @param shellcode: Root of the shellcode tree.

    @type  clazz: class
    @param clazz: Shellcode class to look for. Matching pieces of shellcode
        will be instances of this class or a derived class.

    @rtype:  iterator of L{Shellcode}
    @return: Iterator of matching pieces of shellcode.
    """
    queue = [shellcode]
    while queue:
        shellcode = queue.pop(0)
        if isinstance(shellcode, clazz):
            yield shellcode
        queue = shellcode.children + queue

def find_shellcode(shellcode, clazz):
    """
    Find the first matching piece of shellcode
    that is an instance of the given class.

    @type  shellcode: L{Shellcode}
    @param shellcode: Root of the shellcode tree.

    @type  clazz: class
    @param clazz: Shellcode class to look for. Matching pieces of shellcode
        will be instances of this class or a derived class.

    @rtype:  L{Shellcode}
    @return: Matching piece of shellcode.

    @raise StopIteration: The piece of shellcode was not found.
    """
    return iter_shellcode(shellcode, clazz).next()

#-----------------------------------------------------------------------------#

def load_bytecode_from_source(input):
    """
    Load the bytecode from an exported source code
    generated by the L{shellgen.export} subpackage.

    This function will NOT work with raw binary files, nor hexadecimal dumps,
    nor Base64 encoded files.

    To read exported dump files, use L{load_bytecode_from_dump}() instead.

    @see:
         - L{shellgen.export.as_python_source}
         - L{shellgen.export.as_ruby_source}
         - L{shellgen.export.as_perl_source}
         - L{shellgen.export.as_php_source}
         - L{shellgen.export.as_javascript_source}
         - L{shellgen.export.as_vbscript_source}
         - L{shellgen.export.as_c_source}
         - L{shellgen.export.as_cpp_source}

    @type  input: file or str
    @param input: Filename or open file object.
        Open file objects should be in universal newline mode.

    @rtype:  str
    @return: Imported bytecode.

    @raise IOError: An error has occurred while trying to load the bytecode.
    """

    # Filenames are converted to file objects and garbage collected properly.
    if not hasattr(input, 'readlines'):
        with open(input, 'rU') as input:
            return _load_bytecode_from_source(input)
    return _load_bytecode_from_source(input)

_re_is_line   = re.compile('^[^"]*"[^"]+"[^"]*\\n$')
_re_escape    = re.compile('\\\\x([0-9A-Fa-f][0-9A-Fa-f])')
_re_urlencode = re.compile('\\%([0-9A-Fa-f][0-9A-Fa-f])')

def _load_bytecode_from_source(input):

    # Load the regular expressions as local variables,
    # since we're using them in a loop.
    re_is_line   = _re_is_line
    re_escape    = _re_escape
    re_urlencode = _re_urlencode

    # We'll accumulate the hexadecimal characters here.
    hexa = []

    # Flags to signal errors during parsing.
    bad_line        = False
    found_escape    = False
    found_urlencode = False

    # For each line of text in the input file...
    for line in input.readlines():

        # Skip lines that don't contain bytecode.
        if re_is_line.match(line):

            # Extract escaped char sequences.
            if '\\x' in line:
                found_escape = True
                hexa.extend( re_escape.findall(line) )

            # Extract URL encoded sequences.
            elif '%' in line:
                found_urlencode = True
                hexa.extend( re_urlencode.findall(line) )

            # Flag the error if we found neither.
            else:
                bad_line = True

    # Show warnings if we had parsing errors.
    if bad_line:
        warnings.warn("Bad source code line found, possible load error?")
    if found_escape and found_urlencode:
        warnings.warn("Found both urlencoded and escaped strings,"
                      " possible load error?")

    # Raise an exception if no bytecode was extracted.
    if not hexa:
        raise IOError("No bytecode found, possible load error?")

    # Pack the bytecode and return it.
    hexdump = [int(x, 16) for x in hexa]
    return struct.pack('B' * len(hexdump), hexdump)

#-----------------------------------------------------------------------------#

def load_bytecode_from_dump(input):
    """
    Load the bytecode from an exported dump file
    generated by the L{shellgen.export} subpackage.

    This function will ONLY work with raw binary files, hexadecimal dumps,
    or Base64 encoded files.

    To read source code exports, use L{load_bytecode_from_source}() instead.

    @see:
         - L{shellgen.export.as_raw_binary}
         - L{shellgen.export.as_hexadecimal}
         - L{shellgen.export.as_base64}

    @type  input: file or str
    @param input: Filename or open file object.
        Open file objects should be in binary mode.

    @rtype:  str
    @return: Imported bytecode.

    @raise IOError: An error has occurred while trying to load the bytecode.
    """

    # Filenames are converted to file objects and garbage collected properly.
    if not hasattr(input, 'read'):
        with open(input, 'rb') as input:
            return _load_bytecode_from_dump(input)
    return _load_bytecode_from_dump(input)

_re_is_hexa  = re.compile('^(\\w?[0-9A-Fa-f][0-9A-Fa-f]\\w?)+$')
_re_get_hexa = re.compile('[0-9A-Fa-f]')
_re_is_b64   = re.compile('^[A-Za-z0-9\\+\\/\\n]+\\=?\\=?\\n?$')

def _load_bytecode_from_dump(input):

    # Read the data.
    data = input.read()

    # If it's an hexadecimal dump, decode and return it.
    if _re_is_hexa.match(data):
        hexstr  = ''.join(_re_get_hexa.findall(data))
        hexdump = [ int(hexstr[i:i+2], 16) for i in xrange(0, len(hexstr), 2) ]
        return struct.pack('B' * len(hexdump), hexdump)

    # If it's base64 encoded data, decode and return it.
    if _re_is_b64.match(data):
        return data.decode('base64')

    # Assume it's a raw binary dump and return it unchanged.
    return data

#-----------------------------------------------------------------------------#

def test():
    "Unit test."

    # Static subclasses shouldn't define their own compile() method.
    # This test should have been in base.py, but this particular check
    # is disabled for that module, so we have to do it anywhere else.
    try:
        class TestStaticCompile (Static):
            def compile(self, state):
                #print "Static.compile() suppression failed!"
                assert False

        #print "Static() verification failed!"
        TestStaticCompile().compile()
        assert False
    except TypeError:
        ##raise
        pass

    # Test loading shellcode modules dynamically.
    MyNop = get_shellcode_class('x86', 'any', 'nop', 'Nop')
    from shellgen.x86.nop import Nop
    assert MyNop is Nop
    assert Nop.arch == 'x86'
    assert Nop.os == 'any'
    MyPadder = get_shellcode_class('x86_64', None, 'nop', 'Padder')
    from shellgen.x86_64.nop import Padder
    assert MyPadder is Padder
    assert Padder.arch == 'x86_64'
    assert Padder.os == 'any'
    MyExecute = get_shellcode_class('mips', 'irix', 'execute', 'Execute')
    from shellgen.mips.irix.execute import Execute
    assert MyExecute is Execute
    assert Execute.arch == 'mips'
    assert Execute.os == 'irix'
    try:
        get_shellcode_class('fake', 'fake', 'fake', 'Fake')
        assert False
    except NotImplementedError:
        pass
    except Exception:
        assert False
    try:
        get_shellcode_class('.fake', 'fake', 'fake', 'Fake')
        assert False
    except ValueError:
        pass
    except Exception:
        assert False
    try:
        get_shellcode_class('fake', '/fake', 'fake', 'Fake')
        assert False
    except ValueError:
        pass
    except Exception:
        assert False
    try:
        get_shellcode_class('fake', 'fake', '.fake', 'Fake')
        assert False
    except ValueError:
        pass
    except Exception:
        assert False
    try:
        get_shellcode_class('fake', 'fake', 'fake', 'Fa.ke')
        assert False
    except ValueError:
        pass
    except Exception:
        assert False
    try:
        get_shellcode_class('\\fake', 'fake', 'fake', 'Fake')
        assert False
    except ValueError:
        pass
    except Exception:
        assert False
    try:
        get_shellcode_class('fake', '*fake', 'fake', 'Fake')
        assert False
    except ValueError:
        pass
    except Exception:
        assert False
    try:
        get_shellcode_class('fake', 'fake', 'fake', '_Fake')
        assert False
    except ValueError:
        pass
    except Exception:
        assert False
    platforms = get_available_platforms()
    assert not any(('abstract' in x for x in platforms))
    for arch, os in platforms:
        modules = get_available_modules(arch, os)
##        assert modules        # FIXME uncomment when version 0.1 is released!
        for module in modules:
            if os == 'any':
                mod_path = 'shellgen.%s.%s' % (arch, module)
            else:
                mod_path = 'shellgen.%s.%s.%s' % (arch, os, module)
            classes = get_available_classes(arch, os, module)
            assert classes
            for cls in classes:
                assert cls.__module__ == mod_path
                assert cls.arch == arch or isinstance(cls.arch, property)
                assert   cls.os == os   or isinstance(cls.os, property)

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
    empty_str_encoding = autodetect_encoding('')
    assert empty_str_encoding == autodetect_encoding(None)
    assert empty_str_encoding == Raw('').encoding
    assert empty_str_encoding == Raw(Raw('')).encoding
    assert empty_str_encoding == autodetect_encoding(Raw(''))
    assert 'nullfree' in autodetect_encoding(random_chars(100))
    assert 'nullfree' in Raw(random_chars(100)).encoding
    encoding_test_data = {
        '': ('alpha', 'ascii', 'lower', 'nullfree', 'unicode', 'upper'),
        '\x00': ('alpha', 'ascii', 'lower', 'term_null', 'upper'),
        '\x00\x00': ('alpha', 'ascii', 'lower', 'unicode', 'upper'),
        'hola manola\x00': ('ascii', 'lower', 'term_null'),
        'HOLA MANOLA\x00': ('ascii', 'term_null', 'upper'),
        'Hola Manola': ('ascii', 'nullfree'),
        'matanga\x00': ('alpha', 'ascii', 'lower', 'term_null'),
        'MATANGA\x00': ('alpha', 'ascii', 'term_null', 'upper'),
        'Matanga': ('alpha', 'ascii', 'nullfree'),
        'h\0o\0l\0a\0 \0m\0a\0n\0o\0l\0a\0': ('ascii', 'lower', 'unicode'),
        'h\0o\0l\0a\0 \0m\0a\0n\0o\0l\0a\0\0': ('ascii', 'lower'),              # unaligned size
        '\0h\0o\0l\0a\0 \0m\0a\0n\0o\0l\0a\0\0': ('ascii', 'lower'),            # unaligned address
        'h\0o\0l\0a\0 \0m\0a\0n\0o\0l\0a\0\0\0': ('ascii', 'lower', 'term_null', 'unicode'),
        'M\0A\0T\0A\0N\0G\0A\0': ('alpha', 'ascii', 'unicode', 'upper'),
        'M\0A\0T\0A\0N\0G\0A\0\0': ('alpha', 'ascii', 'upper'),                 # unaligned size
        '\0M\0A\0T\0A\0N\0G\0A\0': ('alpha', 'ascii', 'upper'),                 # unaligned address
        'M\0A\0T\0A\0N\0G\0A\0\0\0': ('alpha', 'ascii', 'term_null', 'unicode', 'upper'),
        'Matanga!': ('ascii', 'nullfree'),
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

    # Test shellcode finding and iteration.
    class TestShellcode1(Static):
        bytes = 'test1'
    class TestShellcode2(Static):
        bytes = 'test2'
    test1 = TestShellcode1()
    test2 = TestShellcode2()
    test3 = test1 + test2
    assert find_shellcode(test3, TestShellcode1) is test1
    assert find_shellcode(test3, TestShellcode2) is test2
    assert find_shellcode(test3, Concatenator)   is test3
    assert list(iter_shellcode(test3, Static)) == [test1, test2]
    assert list(iter_shellcode(test3)) == [test3, test1, test2]

    # Test is_stack_balanced().
    class TestShellcodeUsesStack(Static):
        bytes     = 'test_uses_stack'
        qualities = ''
    class TestShellcodeStackBalanced(Static):
        bytes     = 'test_stack_balanced'
        qualities = 'stack_balanced'
    class TestShellcodeNoStack(Static):
        bytes     = 'test_no_stack'
        qualities = 'no_stack'
    test_uses_stack     = TestShellcodeUsesStack()
    test_stack_balanced = TestShellcodeStackBalanced()
    test_no_stack       = TestShellcodeNoStack()
    assert not is_stack_balanced(test_uses_stack)
    assert is_stack_balanced(test_stack_balanced)
    assert is_stack_balanced(test_no_stack)
    assert is_stack_balanced(test_stack_balanced + test_stack_balanced)
    assert is_stack_balanced(test_no_stack + test_no_stack)
    assert is_stack_balanced(test_stack_balanced + test_no_stack)
    assert is_stack_balanced(test_no_stack + test_stack_balanced)
    assert is_stack_balanced(test_no_stack + test_stack_balanced + test_no_stack)
    assert is_stack_balanced(test_stack_balanced + test_no_stack + test_stack_balanced)
    assert not is_stack_balanced(test_uses_stack + test_uses_stack)
    assert not is_stack_balanced(test_uses_stack + test_stack_balanced)
    assert not is_stack_balanced(test_stack_balanced + test_uses_stack)
    assert not is_stack_balanced(test_uses_stack + test_no_stack)
    assert not is_stack_balanced(test_no_stack + test_uses_stack)
    assert not is_stack_balanced(test_stack_balanced + test_uses_stack + test_stack_balanced)
    assert not is_stack_balanced(test_no_stack + test_uses_stack + test_no_stack)
    assert not is_stack_balanced(test_stack_balanced + test_uses_stack + test_no_stack)
    assert not is_stack_balanced(test_no_stack + test_uses_stack + test_stack_balanced)

    # Test load_bytecode_from_source() and load_bytecode_from_dump().
    from StringIO import StringIO
    from .export import export
    class TestShellcodeExport(Static):
        bytes = struct.pack("B"*250,*range(250))
    test_export = TestShellcodeExport()
    def export_to_str(fmt):
        fd = StringIO()
        export(test_export, fd,fmt)
        return fd.getvalue()
    def test_dump(fmt):
        fd = StringIO(export_to_str(fmt))
        return load_bytecode_from_dump(fd) == test_export.bytes
    def test_src(fmt):
        fd = StringIO(export_to_str(fmt))
        return load_bytecode_from_source(fd) == test_export.bytes
    assert test_dump('raw')
    assert test_dump('hex')
    assert test_dump('base64')
    assert test_src('python')
    assert test_src('ruby')
    assert test_src('perl')
    assert test_src('php')
    assert test_src('javascript')
    assert test_src('vbscript')
    assert test_src('c')
    assert test_src('c++')
    try:
        test_src('raw')
        assert False
    except Exception:
        pass
    try:
        test_src('hex')
        assert False
    except Exception:
        pass
    try:
        test_src('base64')
        assert False
    except Exception:
        pass
    try:
        test_dump('python')
        assert False
    except Exception:
        pass
    try:
        test_dump('ruby')
        assert False
    except Exception:
        pass
    try:
        test_dump('perl')
        assert False
    except Exception:
        pass
    try:
        test_dump('php')
        assert False
    except Exception:
        pass
    try:
        test_dump('javascript')
        assert False
    except Exception:
        pass
    try:
        test_dump('vbscript')
        assert False
    except Exception:
        pass
    try:
        test_dump('c')
        assert False
    except Exception:
        pass
    try:
        test_dump('c++')
        assert False
    except Exception:
        pass
