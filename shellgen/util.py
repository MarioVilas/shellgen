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

__all__ = [
    "get_shellcode_class", "get_available_platforms", "autodetect_encoding",
    "find_bad_chars", "default_bad_chars", "good_chars", "random_chars",
    "is_stack_balanced", "uses_stack", "uses_heap", "uses_seh",
    "print_shellcode_tree",
]

# For unit testing always load this version, not the one installed.
if __name__ == '__main__':
    import sys, os.path
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

    # Now do an absolute import.
    from shellgen.base import *

# Otherwise do a relative import.
else:
    from base import *

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
    arch, os = meta_canonicalize_platform(arch, os)

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

#-----------------------------------------------------------------------------#

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

def is_stack_balanced(shellcode):
    queue = [shellcode]
    while queue:
        shellcode = queue.pop()
        if isinstance(shellcode, Concatenator):
            queue.extend(shellcode.children)
            continue
        if "stack_balanced" in shellcode.qualities:
            continue
        if "no_stack" in shellcode.qualities:
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

# Unit test.
if __name__ == '__main__':
    def test():

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
