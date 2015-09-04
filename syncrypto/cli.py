#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals
import argparse

parser = argparse.ArgumentParser(
    description='Synchronize plaintext folder with its encrypted content'
)

parser.add_argument(
    'encrypted_folder',
    help='The encrypted folder',
    # nargs='?'
)

parser.add_argument(
    'plaintext_folder',
    help='The plaintext folder',
    nargs='?'
)

parser.add_argument(
    '-p',
    '--password',
    help='password'
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
    '-v',
    '--version',
    help='Display the version'
)
