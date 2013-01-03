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

__all__ = ['metadata', 'setup']

from distutils.core import setup
from warnings import warn
from os.path import dirname, curdir, join

# Define the parameters for the setup script.
metadata = {

    # Setup instructions
    'requires'          : [],
    'provides'          : ['shellgen'],
    'packages'          : ['shellgen'],

    # Metadata
    'name'              : 'shellgen',
    'version'           : '0.1',
    'description'       : 'Shellcode generator library',
    'author'            : 'Mario Vilas',
    'author_email'      : 'mvilas'+chr(64)+'gmail'+chr(0x2e)+'com',
    'url'               : 'http://inguma.eu/projects/shellgen',
    'platforms'         : ['win32', 'win64'],
    'classifiers'       : [
                        'License :: OSI Approved :: BSD License',
                        'Development Status :: 1 - Planning',
                        'Intended Audience :: Developers',
                        'Natural Language :: English',
                        'Operating System :: OS Independent',
                        'Programming Language :: Assembly',
                        'Programming Language :: Python :: 2.4',
                        'Programming Language :: Python :: 2.5',
                        'Programming Language :: Python :: 2.6',
                        'Programming Language :: Python :: 2.7',
                        'Topic :: Security',
                        'Topic :: Software Development :: Assemblers',
                        'Topic :: Software Development :: Libraries :: Python Modules',
                        ],
    }

# Read the long description from the README file.
try:
    here = dirname(__file__)
    if not here:
        here = curdir
    readme = join(here, 'README')
    long_description = open(readme, 'r').read()
    metadata['long_description'] = long_description
except Exception:
    warn("README file not found or unreadable!")

# Execute the setup script.
if __name__ == '__main__':
    setup(**metadata)
