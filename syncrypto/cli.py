#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2015 Qing Liang (https://github.com/liangqing)
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

from __future__ import unicode_literals
import argparse
from .package_info import __doc__

parser = argparse.ArgumentParser(
    description=__doc__
)

parser.add_argument(
    'encrypted_folder',
    help='The encrypted folder',
    nargs='?'
)

parser.add_argument(
    'plaintext_folder',
    help='The plaintext folder',
    nargs='?'
)

parser.add_argument(
    '--password-file',
    help=("Use the password in the file instead of "
          "getting it from interactive input")
)

parser.add_argument(
    '--change-password',
    action='store_true',
    help='Change the password of an encrypted folder'
)

parser.add_argument(
    '--clear-encrypted-folder',
    action='store_true',
    help='Clear the files in encrypted folder'
)

parser.add_argument(
    '--print-encrypted-tree',
    action='store_true',
    help='Print the file tree in encrypted folder'
)

parser.add_argument(
    '--decrypt-file',
    help=('Decrypt a file, it will store the result plaintext file in current '
          'directory unless you specify --out-file option')
)

parser.add_argument(
    '--out-file',
    help='When decrypting a file, specify the output plaintext file path'
)

parser.add_argument(
    '--interval',
    type=int,
    help='Sync directory every interval seconds'
)

parser.add_argument(
    '--rule-file',
    help='Specify the rule file, default is [plaintext folder]/.syncrypto/rules'
)

parser.add_argument(
    '--rule',
    action="append",
    help='Add file include or exclude rule'
)

parser.add_argument(
    '--debug',
    action="store_true",
    help='Debug mode'
)

parser.add_argument(
    '--version',
    action="store_true",
    help='Display the version'
)
