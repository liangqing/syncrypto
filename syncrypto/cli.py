#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse

parser = argparse.ArgumentParser(
    description='Sync files between folders in encrypted way'
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
    '--include',
    action="append",
    help='include the file or directory match it'
)

parser.add_argument(
    '--exclude',
    action="append",
    help='exclude the file or directory match it'
)
