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

__all__ = ['metadata', 'setup']

from distutils.core import setup, Command
from warnings import warn
from os import walk
from os.path import abspath, dirname, curdir, join, isdir, isfile, sep

# Define the parameters for the setup script.
metadata = {

    # Setup instructions
    'requires'          : [],
    'provides'          : ['shellgen'],

    # Metadata
    'name'              : 'shellgen',
    'version'           : '0.1',
    'description'       : 'Shellcode generator library',
    'author'            : 'Mario Vilas',
    'author_email'      : 'mvilas'+chr(64)+'gmail'+chr(0x2e)+'com',
    'url'               : 'http://inguma.eu/projects/shellgen',
    'classifiers'       : [
                        'License :: OSI Approved :: BSD License',
                        'Development Status :: 1 - Planning',
                        'Intended Audience :: Developers',
                        'Natural Language :: English',
                        'Operating System :: OS Independent',
                        'Programming Language :: Assembly',
                        'Programming Language :: Python :: 2.5',
                        'Programming Language :: Python :: 2.6',
                        'Programming Language :: Python :: 2.7',
                        'Topic :: Security',
                        'Topic :: Software Development :: Assemblers',
                        'Topic :: Software Development :: Libraries :: Python Modules',
                        ],
    }

# Find out where we are.
here = dirname(__file__)
if not here:
    here = curdir
here = abspath(here)

# Automatically find all subpackages.
packages = ['shellgen']
for root, folders, files in walk(join(here, 'shellgen')):
    if '__init__.py' in files:
        module = root[len(here):]
        if module.startswith(sep):
            module = module[len(sep):]
        if module.endswith(sep):
            module = module[:-len(sep)]
        module = module.replace(sep, '.')
        packages.append(module)
packages.sort()
metadata['packages'] = packages

# Read the long description from the README file.
try:
    readme = join(here, 'README')
    long_description = open(readme, 'r').read()
    metadata['long_description'] = long_description
except Exception:
    warn("README file not found or unreadable!")

# The test suite.
class TestCommand(Command):

    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        import sys
        sys.path.insert(0, dirname(__file__))
        print "testing shellgen.base"
        from shellgen.base import test
        test()
        print "testing shellgen.util"
        from shellgen.util import test
        test()
        print "testing shellgen.payload"
        from shellgen.payload import test
        test()
        print "testing shellgen.export"
        from shellgen.export import test
        test()
        from shellgen.util import get_available_platforms, \
                                  get_available_modules
        for module in get_available_modules("abstract", "any"):
            self.__test_module("abstract", "any", module)
        for arch, os in get_available_platforms():
            for module in get_available_modules(arch, os):
                self.__test_module(arch, os, module)

    def __test_module(self, arch, os, module):
        if os == "any":
            module_path = "shellgen.%s.%s" % (arch, module)
        else:
            module_path = "shellgen.%s.%s.%s" % (arch, os, module)
        try:
            modobj = __import__(module_path, fromlist = ["test"])
            test   = getattr(modobj, "test")
        except ImportError:
            return
        except AttributeError:
            return
        print "testing " + module_path
        test()

# Add the 'test' command.
metadata['cmdclass'] = {'test': TestCommand}

# Execute the setup script.
if __name__ == '__main__':
    setup(**metadata)
